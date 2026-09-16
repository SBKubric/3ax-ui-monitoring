package retention

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
)

// testTime is where the fake clock of every test starts.
var testTime = time.Date(2025, 9, 13, 10, 0, 0, 0, time.UTC)

// Ages in the storage unit, milliseconds.
const (
	hour = int64(time.Hour / time.Millisecond)
	day  = 24 * hour
	week = 7 * day
	year = 365 * day
)

// openStore opens a store on a fresh file driven by a fake clock, so the
// retention cutoffs are exactly where the test puts them.
func openStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "mon-server.db"), nil, store.WithClock(clock.NewFake(testTime)))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() {
		if err := st.Close(); err != nil {
			t.Errorf("store.Close: %v", err)
		}
	})
	return st
}

// ptr is the address of v, for the nullable sent_at columns.
func ptr[T any](v T) *T { return &v }

// create inserts one row, failing the test if it cannot.
func create(tb testing.TB, st *store.Store, row any) {
	tb.Helper()
	if err := st.DB().Create(row).Error; err != nil {
		tb.Fatalf("seed %T: %v", row, err)
	}
}

// seedEvent files one outbox event. sentAt is nil while the panel has not
// accepted it.
func seedEvent(tb testing.TB, st *store.Store, id string, ts int64, sentAt *int64) {
	tb.Helper()
	create(tb, st, &store.EventOutbox{ID: id, TS: ts, Payload: `{"kind":"target"}`, SentAt: sentAt})
}

// seedBucket files one stats bucket. bucketStart keeps the identity index
// unique, sentAt is nil until the panel has accepted it.
func seedBucket(tb testing.TB, st *store.Store, bucketStart int64, sentAt *int64) {
	tb.Helper()
	create(tb, st, &store.StatsBucket{
		MonClientID: "ams-1",
		InboundKind: store.InboundKindXray,
		InboundID:   7,
		Path:        store.PathDirect,
		BucketStart: bucketStart,
		NOk:         3,
		SentAt:      sentAt,
	})
}

// seedProbeSeen files one tunnel probe diagnostics row.
func seedProbeSeen(tb testing.TB, st *store.Store, seenAt int64) {
	tb.Helper()
	create(tb, st, &store.ProbeSeen{
		MonClientID: "ams-1",
		InboundKind: store.InboundKindXray,
		InboundID:   7,
		Path:        store.PathProxy,
		EgressIP:    "203.0.113.9",
		SeenAt:      seenAt,
	})
}

// seedRequest files one registration request in the given status.
func seedRequest(tb testing.TB, st *store.Store, id, status string, createdAt int64) {
	tb.Helper()
	create(tb, st, &store.RegistrationRequest{
		RequestID:   id,
		PairingCode: "A2B3C4",
		Hostname:    "probe-ams-1",
		Version:     "1.0.0",
		PublicIP:    "203.0.113.9",
		RemoteIP:    "203.0.113.9",
		Status:      status,
		CreatedAt:   createdAt,
		ExpiresAt:   createdAt + 5*60_000,
	})
}

// seedSession files one admin cookie session.
func seedSession(tb testing.TB, st *store.Store, id string, expiresAt int64) {
	tb.Helper()
	create(tb, st, &store.AdminSession{
		ID:        id,
		CreatedAt: expiresAt - day,
		ExpiresAt: expiresAt,
		IP:        "198.51.100.4",
	})
}

// count is how many rows the table of model still holds.
func count(tb testing.TB, st *store.Store, model any) int64 {
	tb.Helper()
	var n int64
	if err := st.DB().Model(model).Count(&n).Error; err != nil {
		tb.Fatalf("count %T: %v", model, err)
	}
	return n
}

// cancelOnFirstDelete cancels ctx as soon as one batch has actually removed
// rows. It is how the tests interrupt a sweep between batches: deterministic,
// no sleeping and no ticker.
func cancelOnFirstDelete(tb testing.TB, st *store.Store, cancel context.CancelFunc) {
	tb.Helper()
	const name = "test:cancel_after_delete"
	var once sync.Once
	err := st.DB().Callback().Raw().After("gorm:raw").Register(name, func(db *gorm.DB) {
		if db.Error == nil && db.RowsAffected > 0 {
			once.Do(cancel)
		}
	})
	if err != nil {
		tb.Fatalf("register callback: %v", err)
	}
	tb.Cleanup(func() {
		if err := st.DB().Callback().Raw().Remove(name); err != nil {
			tb.Errorf("remove callback: %v", err)
		}
	})
}

// TestRunOnce_Windows walks every retention rule of spec §3 at its boundary:
// one millisecond inside the window, exactly at it, one millisecond past it —
// and the rows that must survive whatever their age.
func TestRunOnce_Windows(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		model any
		seed  func(tb testing.TB, st *store.Store, now int64)
		kept  bool
	}{{
		name:  "delivered event one millisecond inside the window stays",
		model: &store.EventOutbox{},
		seed: func(tb testing.TB, st *store.Store, now int64) {
			seedEvent(tb, st, "ev", now-week, ptr(now-week+1))
		},
		kept: true,
	}, {
		name:  "delivered event exactly at the window stays",
		model: &store.EventOutbox{},
		seed: func(tb testing.TB, st *store.Store, now int64) {
			seedEvent(tb, st, "ev", now-week, ptr(now-week))
		},
		kept: true,
	}, {
		name:  "delivered event one millisecond past the window goes",
		model: &store.EventOutbox{},
		seed: func(tb testing.TB, st *store.Store, now int64) {
			seedEvent(tb, st, "ev", now-week-1, ptr(now-week-1))
		},
	}, {
		// The panel has not taken it yet; during a long PANEL_DOWN the outbox
		// is the only copy there is.
		name:  "undelivered event stays however old",
		model: &store.EventOutbox{},
		seed: func(tb testing.TB, st *store.Store, now int64) {
			seedEvent(tb, st, "ev", now-year, nil)
		},
		kept: true,
	}, {
		name:  "delivered bucket one millisecond inside the window stays",
		model: &store.StatsBucket{},
		seed: func(tb testing.TB, st *store.Store, now int64) {
			seedBucket(tb, st, now-week, ptr(now-week+1))
		},
		kept: true,
	}, {
		name:  "delivered bucket exactly at the window stays",
		model: &store.StatsBucket{},
		seed: func(tb testing.TB, st *store.Store, now int64) {
			seedBucket(tb, st, now-week, ptr(now-week))
		},
		kept: true,
	}, {
		name:  "delivered bucket one millisecond past the window goes",
		model: &store.StatsBucket{},
		seed: func(tb testing.TB, st *store.Store, now int64) {
			seedBucket(tb, st, now-week-1, ptr(now-week-1))
		},
	}, {
		name:  "undelivered bucket stays however old",
		model: &store.StatsBucket{},
		seed: func(tb testing.TB, st *store.Store, now int64) {
			seedBucket(tb, st, now-year, nil)
		},
		kept: true,
	}, {
		name:  "probe seen one millisecond inside the window stays",
		model: &store.ProbeSeen{},
		seed: func(tb testing.TB, st *store.Store, now int64) {
			seedProbeSeen(tb, st, now-day+1)
		},
		kept: true,
	}, {
		name:  "probe seen exactly at the window stays",
		model: &store.ProbeSeen{},
		seed: func(tb testing.TB, st *store.Store, now int64) {
			seedProbeSeen(tb, st, now-day)
		},
		kept: true,
	}, {
		name:  "probe seen one millisecond past the window goes",
		model: &store.ProbeSeen{},
		seed: func(tb testing.TB, st *store.Store, now int64) {
			seedProbeSeen(tb, st, now-day-1)
		},
	}, {
		name:  "rejected request one millisecond inside the window stays",
		model: &store.RegistrationRequest{},
		seed: func(tb testing.TB, st *store.Store, now int64) {
			seedRequest(tb, st, "rq", store.RequestRejected, now-week+1)
		},
		kept: true,
	}, {
		name:  "rejected request exactly at the window stays",
		model: &store.RegistrationRequest{},
		seed: func(tb testing.TB, st *store.Store, now int64) {
			seedRequest(tb, st, "rq", store.RequestRejected, now-week)
		},
		kept: true,
	}, {
		name:  "rejected request one millisecond past the window goes",
		model: &store.RegistrationRequest{},
		seed: func(tb testing.TB, st *store.Store, now int64) {
			seedRequest(tb, st, "rq", store.RequestRejected, now-week-1)
		},
	}, {
		name:  "expired request past the window goes",
		model: &store.RegistrationRequest{},
		seed: func(tb testing.TB, st *store.Store, now int64) {
			seedRequest(tb, st, "rq", store.RequestExpired, now-week-1)
		},
	}, {
		name:  "approved request past the window goes",
		model: &store.RegistrationRequest{},
		seed: func(tb testing.TB, st *store.Store, now int64) {
			seedRequest(tb, st, "rq", store.RequestApproved, now-week-1)
		},
	}, {
		// A pending request is live registration state, not history.
		name:  "pending request stays however old",
		model: &store.RegistrationRequest{},
		seed: func(tb testing.TB, st *store.Store, now int64) {
			seedRequest(tb, st, "rq", store.RequestPending, now-year)
		},
		kept: true,
	}, {
		name:  "session expiring in a millisecond stays",
		model: &store.AdminSession{},
		seed: func(tb testing.TB, st *store.Store, now int64) {
			seedSession(tb, st, "sid", now+1)
		},
		kept: true,
	}, {
		name:  "session expiring exactly now stays",
		model: &store.AdminSession{},
		seed: func(tb testing.TB, st *store.Store, now int64) {
			seedSession(tb, st, "sid", now)
		},
		kept: true,
	}, {
		name:  "session expired a millisecond ago goes",
		model: &store.AdminSession{},
		seed: func(tb testing.TB, st *store.Store, now int64) {
			seedSession(tb, st, "sid", now-1)
		},
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			st := openStore(t)
			now := st.NowMS()
			tc.seed(t, st, now)

			res, err := New(st, nil).RunOnce(t.Context())
			if err != nil {
				t.Fatalf("RunOnce: %v", err)
			}

			want := int64(0)
			if tc.kept {
				want = 1
			}
			if got := count(t, st, tc.model); got != want {
				t.Errorf("rows left = %d, want %d", got, want)
			}
			if got := res.Total(); got != 1-want {
				t.Errorf("Result.Total() = %d, want %d (%+v)", got, 1-want, res)
			}
		})
	}
}

// TestRunOnce_CountsEveryTable sweeps all five tables in one run and checks
// both the per-table counts and what is left behind.
func TestRunOnce_CountsEveryTable(t *testing.T) {
	t.Parallel()
	st := openStore(t)
	now := st.NowMS()

	// Two delivered events past the window, one delivered inside it, one
	// ancient but still owed to the panel.
	seedEvent(t, st, "ev-old-1", now-week-hour, ptr(now-week-hour))
	seedEvent(t, st, "ev-old-2", now-week-day, ptr(now-week-day))
	seedEvent(t, st, "ev-fresh", now-day, ptr(now-day))
	seedEvent(t, st, "ev-unsent", now-year, nil)

	seedBucket(t, st, now-week-hour, ptr(now-week-hour))
	seedBucket(t, st, now-hour, ptr(now-hour))
	seedBucket(t, st, now-year, nil)

	seedProbeSeen(t, st, now-day-1)
	seedProbeSeen(t, st, now-day-hour)
	seedProbeSeen(t, st, now-hour)

	seedRequest(t, st, "rq-rejected", store.RequestRejected, now-week-hour)
	seedRequest(t, st, "rq-pending", store.RequestPending, now-week-hour)
	seedRequest(t, st, "rq-approved-fresh", store.RequestApproved, now-hour)

	seedSession(t, st, "sid-expired", now-hour)
	seedSession(t, st, "sid-live", now+hour)

	res, err := New(st, nil).RunOnce(t.Context())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	want := Result{Events: 2, Stats: 1, ProbeSeen: 2, Requests: 1, Sessions: 1}
	if res != want {
		t.Errorf("Result = %+v, want %+v", res, want)
	}

	left := []struct {
		model any
		want  int64
	}{
		{&store.EventOutbox{}, 2},
		{&store.StatsBucket{}, 2},
		{&store.ProbeSeen{}, 1},
		{&store.RegistrationRequest{}, 2},
		{&store.AdminSession{}, 1},
	}
	for _, l := range left {
		if got := count(t, st, l.model); got != l.want {
			t.Errorf("%T rows left = %d, want %d", l.model, got, l.want)
		}
	}

	// The survivors are the right ones, not merely the right number.
	var unsent int64
	if err := st.DB().Model(&store.EventOutbox{}).Where("sent_at IS NULL").Count(&unsent).Error; err != nil {
		t.Fatalf("count unsent events: %v", err)
	}
	if unsent != 1 {
		t.Errorf("unsent events left = %d, want 1", unsent)
	}
	var pending int64
	if err := st.DB().Model(&store.RegistrationRequest{}).Where("status = ?", store.RequestPending).Count(&pending).Error; err != nil {
		t.Fatalf("count pending requests: %v", err)
	}
	if pending != 1 {
		t.Errorf("pending requests left = %d, want 1", pending)
	}

	// A second sweep at the same instant has nothing left to do.
	again, err := New(st, nil).RunOnce(t.Context())
	if err != nil {
		t.Fatalf("second RunOnce: %v", err)
	}
	if !again.IsZero() {
		t.Errorf("second Result = %+v, want zero", again)
	}
}

// TestRunOnce_Batching seeds more rows than one batch holds and checks that
// the bounded loop still removes all of them and counts them once.
func TestRunOnce_Batching(t *testing.T) {
	t.Parallel()
	st := openStore(t)
	now := st.NowMS()

	const (
		batch      = 10
		staleProbe = 25
		freshProbe = 4
		staleEvent = 23
	)
	for i := range staleProbe {
		seedProbeSeen(t, st, now-day-1-int64(i))
	}
	for i := range freshProbe {
		seedProbeSeen(t, st, now-hour-int64(i))
	}
	for i := range staleEvent {
		sent := now - week - 1 - int64(i)
		seedEvent(t, st, fmt.Sprintf("ev-%02d", i), sent, ptr(sent))
	}

	res, err := New(st, nil, WithBatchSize(batch)).RunOnce(t.Context())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if res.ProbeSeen != staleProbe {
		t.Errorf("Result.ProbeSeen = %d, want %d", res.ProbeSeen, staleProbe)
	}
	if res.Events != staleEvent {
		t.Errorf("Result.Events = %d, want %d", res.Events, staleEvent)
	}
	if got := count(t, st, &store.ProbeSeen{}); got != freshProbe {
		t.Errorf("probe_seen rows left = %d, want %d", got, freshProbe)
	}
	if got := count(t, st, &store.EventOutbox{}); got != 0 {
		t.Errorf("events_outbox rows left = %d, want 0", got)
	}
}

// TestRunOnce_BatchCap checks the bound on one sweep: a backlog larger than
// the cap is trimmed in one bounded burst and the rest waits for the next run,
// instead of holding the single writer connection until it is done.
func TestRunOnce_BatchCap(t *testing.T) {
	t.Parallel()
	st := openStore(t)
	now := st.NowMS()

	const rows = maxBatchesPerTable + 5
	for i := range rows {
		seedProbeSeen(t, st, now-day-1-int64(i))
	}

	j := New(st, nil, WithBatchSize(1))
	res, err := j.RunOnce(t.Context())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if res.ProbeSeen != maxBatchesPerTable {
		t.Errorf("Result.ProbeSeen = %d, want %d", res.ProbeSeen, maxBatchesPerTable)
	}
	if got := count(t, st, &store.ProbeSeen{}); got != rows-maxBatchesPerTable {
		t.Errorf("probe_seen rows left = %d, want %d", got, rows-maxBatchesPerTable)
	}

	// The next run picks up where this one stopped.
	if _, err := New(st, nil).RunOnce(t.Context()); err != nil {
		t.Fatalf("second RunOnce: %v", err)
	}
	if got := count(t, st, &store.ProbeSeen{}); got != 0 {
		t.Errorf("probe_seen rows left after the second run = %d, want 0", got)
	}
}

// TestRunOnce_Empty is the normal case on a quiet installation.
func TestRunOnce_Empty(t *testing.T) {
	t.Parallel()
	st := openStore(t)

	res, err := New(st, nil).RunOnce(t.Context())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if res != (Result{}) {
		t.Errorf("Result = %+v, want the zero struct", res)
	}
	if !res.IsZero() {
		t.Errorf("Result.IsZero() = false for %+v", res)
	}
}

// TestRunOnce_ContextCancelled covers both ways a shutdown can catch the job:
// before it starts and between two batches.
func TestRunOnce_ContextCancelled(t *testing.T) {
	t.Parallel()

	t.Run("cancelled before the sweep starts", func(t *testing.T) {
		t.Parallel()
		st := openStore(t)
		now := st.NowMS()
		seedProbeSeen(t, st, now-day-1)
		seedSession(t, st, "sid", now-1)

		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		res, err := New(st, nil).RunOnce(ctx)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("RunOnce error = %v, want context.Canceled", err)
		}
		if !res.IsZero() {
			t.Errorf("Result = %+v, want zero", res)
		}
		if got := count(t, st, &store.ProbeSeen{}); got != 1 {
			t.Errorf("probe_seen rows left = %d, want 1", got)
		}
		if got := count(t, st, &store.AdminSession{}); got != 1 {
			t.Errorf("admin_sessions rows left = %d, want 1", got)
		}
	})

	t.Run("cancelled between batches", func(t *testing.T) {
		t.Parallel()
		st := openStore(t)
		now := st.NowMS()

		const (
			batch = 5
			rows  = 20
		)
		for i := range rows {
			seedProbeSeen(t, st, now-day-1-int64(i))
		}
		seedSession(t, st, "sid", now-1)

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		cancelOnFirstDelete(t, st, cancel)

		res, err := New(st, nil, WithBatchSize(batch)).RunOnce(ctx)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("RunOnce error = %v, want context.Canceled", err)
		}
		if res.ProbeSeen != batch {
			t.Errorf("Result.ProbeSeen = %d, want %d", res.ProbeSeen, batch)
		}
		// What the Result claims and what the database holds agree: batches
		// are whole statements, nothing is half-deleted.
		if got := count(t, st, &store.ProbeSeen{}); got != rows-res.ProbeSeen {
			t.Errorf("probe_seen rows left = %d, want %d", got, rows-res.ProbeSeen)
		}
		// The sweep stopped before reaching admin_sessions.
		if got := count(t, st, &store.AdminSession{}); got != 1 {
			t.Errorf("admin_sessions rows left = %d, want 1", got)
		}

		// A later run finishes the job.
		rest, err := New(st, nil).RunOnce(t.Context())
		if err != nil {
			t.Fatalf("RunOnce after cancellation: %v", err)
		}
		if rest.ProbeSeen != rows-res.ProbeSeen {
			t.Errorf("second Result.ProbeSeen = %d, want %d", rest.ProbeSeen, rows-res.ProbeSeen)
		}
		if got := count(t, st, &store.ProbeSeen{}); got != 0 {
			t.Errorf("probe_seen rows left after the second run = %d, want 0", got)
		}
		if got := count(t, st, &store.AdminSession{}); got != 0 {
			t.Errorf("admin_sessions rows left after the second run = %d, want 0", got)
		}
	})
}

// TestRun_StopsOnContextDone drives the loop itself, without waiting on the
// hourly ticker: the context is cancelled before the first sweep in one case
// and during it in the other.
func TestRun_StopsOnContextDone(t *testing.T) {
	t.Parallel()

	t.Run("cancelled before the first sweep", func(t *testing.T) {
		t.Parallel()
		st := openStore(t)
		seedProbeSeen(t, st, st.NowMS()-day-1)

		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		if err := New(st, nil).Run(ctx); err != nil {
			t.Fatalf("Run: %v", err)
		}
		if got := count(t, st, &store.ProbeSeen{}); got != 1 {
			t.Errorf("probe_seen rows left = %d, want 1 (nothing should have been swept)", got)
		}
	})

	t.Run("cancelled during the first sweep", func(t *testing.T) {
		t.Parallel()
		st := openStore(t)
		now := st.NowMS()
		for i := range 10 {
			seedProbeSeen(t, st, now-day-1-int64(i))
		}

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		cancelOnFirstDelete(t, st, cancel)

		// A one-hour interval: if Run waited for the ticker the test would
		// time out, so returning at all proves it stops on ctx.Done.
		if err := New(st, nil, WithBatchSize(3)).Run(ctx); err != nil {
			t.Fatalf("Run: %v", err)
		}
		if got := count(t, st, &store.ProbeSeen{}); got != 7 {
			t.Errorf("probe_seen rows left = %d, want 7", got)
		}
	})
}

// TestNew_Defaults pins the windows of spec §3 and the guard that keeps a
// nonsense option from widening them.
func TestNew_Defaults(t *testing.T) {
	t.Parallel()
	st := openStore(t)

	j := New(st, nil)
	if j.interval != time.Hour {
		t.Errorf("interval = %v, want 1h", j.interval)
	}
	if j.batch != DefaultBatchSize {
		t.Errorf("batch = %d, want %d", j.batch, DefaultBatchSize)
	}
	for _, c := range []struct {
		name string
		got  time.Duration
		want time.Duration
	}{
		{"eventTTL", j.eventTTL, 7 * 24 * time.Hour},
		{"statsTTL", j.statsTTL, 7 * 24 * time.Hour},
		{"probeSeenTTL", j.probeSeenTTL, 24 * time.Hour},
		{"requestTTL", j.requestTTL, 7 * 24 * time.Hour},
	} {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.name, c.got, c.want)
		}
	}
	// The Janitor shares the store's clock unless told otherwise.
	if j.clk != st.Clock() {
		t.Errorf("clock = %v, want the store's clock", j.clk)
	}

	guarded := New(st, nil,
		WithBatchSize(0),
		WithInterval(-time.Second),
		WithEventTTL(0),
		WithStatsTTL(-time.Hour),
		WithProbeSeenTTL(0),
		WithRequestTTL(0),
		WithClock(nil),
	)
	same := guarded.interval == j.interval &&
		guarded.batch == j.batch &&
		guarded.eventTTL == j.eventTTL &&
		guarded.statsTTL == j.statsTTL &&
		guarded.probeSeenTTL == j.probeSeenTTL &&
		guarded.requestTTL == j.requestTTL &&
		guarded.clk == j.clk
	if !same {
		t.Errorf("options that are not positive changed the job: %+v, want %+v", *guarded, *j)
	}
}
