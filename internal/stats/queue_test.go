package stats_test

import (
	"context"
	"testing"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
	"github.com/SBKubric/3ax-ui-monitoring/internal/panel"
	"github.com/SBKubric/3ax-ui-monitoring/internal/state"
	"github.com/SBKubric/3ax-ui-monitoring/internal/stats"
)

// closed reads the ready buckets, failing the test on an error.
func closed(t *testing.T, r *stats.Recorder, limit int) []panel.Stat {
	t.Helper()
	out, err := r.Closed(context.Background(), limit)
	if err != nil {
		t.Fatalf("closed buckets: %v", err)
	}
	return out
}

// TestClosedWaitsAMinutePastTheWindow is the closing rule of spec §7.4 through
// the queue: a bucket is only offered for POST /stats one minute after the end
// of its window, and not a millisecond before.
func TestClosedWaitsAMinutePastTheWindow(t *testing.T) {
	r, _, clk := newRecorder(t)
	record(t, r, cycle{ts: testOrigin + 120_000, results: []state.Result{res(xray, 12, proxy, true, p(41), nil)}})

	clk.Set(clock.FromMS(stats.ClosesAt(testOrigin) - 1))
	if got := closed(t, r, panel.MaxStats); len(got) != 0 {
		t.Fatalf("got %d buckets one millisecond early, want none: %+v", len(got), got)
	}

	clk.Advance(time.Millisecond)
	got := closed(t, r, panel.MaxStats)
	if len(got) != 1 {
		t.Fatalf("got %d buckets at closing time, want one: %+v", len(got), got)
	}
	want := panel.Stat{
		MonClientID: clientID, InboundKind: xray, InboundID: 12, Path: proxy,
		BucketStart: testOrigin, NOk: 1, NFail: 0,
		LatencyMinMS: p(41), LatencyAvgMS: p(41), LatencyMaxMS: p(41),
	}
	assertStat(t, got[0], want)
}

// TestClosedIsOldestFirstAndBounded covers the batch the dispatcher asks for:
// oldest window first, no more than the limit, and ClosedFrom stepping over
// the head of the queue.
func TestClosedIsOldestFirstAndBounded(t *testing.T) {
	r, _, clk := newRecorder(t)
	for i := range 4 {
		ts := testOrigin + int64(i)*stats.WindowMS + 1_000
		record(t, r, cycle{ts: ts, results: []state.Result{res(xray, 12, proxy, true, p(41), nil)}})
	}
	// Far enough past the last window that every bucket is closed.
	clk.Set(clock.FromMS(stats.ClosesAt(testOrigin + 3*stats.WindowMS)))

	all := closed(t, r, panel.MaxStats)
	if len(all) != 4 {
		t.Fatalf("got %d closed buckets, want 4: %+v", len(all), all)
	}
	for i, stat := range all {
		if want := testOrigin + int64(i)*stats.WindowMS; stat.BucketStart != want {
			t.Errorf("bucket %d starts at %d, want %d: the queue is not oldest first", i, stat.BucketStart, want)
		}
	}

	head := closed(t, r, 2)
	if len(head) != 2 || head[0].BucketStart != testOrigin {
		t.Fatalf("limited read = %+v, want the two oldest", head)
	}
	rest, err := r.ClosedFrom(context.Background(), 2, panel.MaxStats)
	if err != nil {
		t.Fatalf("closed from 2: %v", err)
	}
	if len(rest) != 2 || rest[0].BucketStart != testOrigin+2*stats.WindowMS {
		t.Fatalf("skipped read = %+v, want the two newest", rest)
	}
}

// TestClosedReportsNoLatencyWithoutASuccess is contract §4.7: with nOk 0 every
// latency field is null, never zero.
func TestClosedReportsNoLatencyWithoutASuccess(t *testing.T) {
	r, _, clk := newRecorder(t)
	record(t, r, cycle{ts: testOrigin + 1_000, results: []state.Result{
		res(xray, 12, proxy, false, nil, nil),
		res(awg, 0, direct, false, nil, nil),
	}})
	clk.Set(clock.FromMS(stats.ClosesAt(testOrigin)))

	for _, stat := range closed(t, r, panel.MaxStats) {
		if stat.NOk != 0 || stat.NFail != 1 {
			t.Errorf("nOk/nFail = %d/%d, want 0/1", stat.NOk, stat.NFail)
		}
		if stat.LatencyMinMS != nil || stat.LatencyAvgMS != nil || stat.LatencyMaxMS != nil {
			t.Errorf("latency is %s/%s/%s, want NULL everywhere",
				show(stat.LatencyMinMS), show(stat.LatencyAvgMS), show(stat.LatencyMaxMS))
		}
		if stat.HandshakeMS != nil {
			t.Errorf("handshakeMs = %s, want NULL", show(stat.HandshakeMS))
		}
	}
}

// TestMarkSentTakesBucketsOutOfTheQueue is the other half of the seam: a
// bucket the panel accepted is stamped and never offered again.
func TestMarkSentTakesBucketsOutOfTheQueue(t *testing.T) {
	r, st, clk := newRecorder(t)
	record(t, r, cycle{ts: testOrigin + 1_000, results: []state.Result{res(xray, 12, proxy, true, p(41), nil)}})
	clk.Set(clock.FromMS(stats.ClosesAt(testOrigin)))

	ready := closed(t, r, panel.MaxStats)
	at := clock.MS(clk.Now())
	if err := r.MarkSent(context.Background(), ready, at); err != nil {
		t.Fatalf("mark sent: %v", err)
	}
	if got := closed(t, r, panel.MaxStats); len(got) != 0 {
		t.Fatalf("got %d buckets after delivery, want none: %+v", len(got), got)
	}
	row := onlyBucket(t, st)
	if row.SentAt == nil || *row.SentAt != at {
		t.Errorf("sent_at = %s, want %d", show(row.SentAt), at)
	}
}

// TestLateCycleClearsSentAt is the resend rule of spec §7.4: a cycle that
// arrives after its bucket was delivered changes the aggregate, so the bucket
// goes back into the queue and the panel upserts the corrected figures.
func TestLateCycleClearsSentAt(t *testing.T) {
	r, st, clk := newRecorder(t)
	record(t, r, cycle{ts: testOrigin + 1_000, results: []state.Result{res(xray, 12, proxy, true, p(41), nil)}})
	clk.Set(clock.FromMS(stats.ClosesAt(testOrigin)))

	ready := closed(t, r, panel.MaxStats)
	if err := r.MarkSent(context.Background(), ready, clock.MS(clk.Now())); err != nil {
		t.Fatalf("mark sent: %v", err)
	}

	// An hour later the mon-client resends the cycle it never had
	// acknowledged. It belongs to the same window.
	clk.Advance(time.Hour)
	record(t, r, cycle{
		ts: testOrigin + 61_000, unverified: true,
		results: []state.Result{res(xray, 12, proxy, true, p(47), nil)},
	})

	row := onlyBucket(t, st)
	if row.SentAt != nil {
		t.Fatalf("sent_at = %s, want NULL: the changed bucket must go out again", show(row.SentAt))
	}
	again := closed(t, r, panel.MaxStats)
	if len(again) != 1 {
		t.Fatalf("got %d buckets, want the changed one back in the queue: %+v", len(again), again)
	}
	assertStat(t, again[0], panel.Stat{
		MonClientID: clientID, InboundKind: xray, InboundID: 12, Path: proxy,
		BucketStart: testOrigin, NOk: 2, NFail: 0,
		LatencyMinMS: p(41), LatencyAvgMS: p(44), LatencyMaxMS: p(47),
	})
}

// TestMarkSentLeavesAChangedBucketQueued guards the window between reading a
// batch and the panel answering it: a cycle that landed in the meantime must
// not be marked delivered, because the panel never saw those figures.
func TestMarkSentLeavesAChangedBucketQueued(t *testing.T) {
	r, st, clk := newRecorder(t)
	record(t, r, cycle{ts: testOrigin + 1_000, results: []state.Result{res(xray, 12, proxy, true, p(41), nil)}})
	clk.Set(clock.FromMS(stats.ClosesAt(testOrigin)))

	inFlight := closed(t, r, panel.MaxStats)
	record(t, r, cycle{ts: testOrigin + 61_000, results: []state.Result{res(xray, 12, proxy, false, nil, nil)}})
	if err := r.MarkSent(context.Background(), inFlight, clock.MS(clk.Now())); err != nil {
		t.Fatalf("mark sent: %v", err)
	}

	row := onlyBucket(t, st)
	if row.SentAt != nil {
		t.Errorf("sent_at = %s, want NULL: the bucket changed while it was in flight", show(row.SentAt))
	}
	if got := closed(t, r, panel.MaxStats); len(got) != 1 || got[0].NFail != 1 {
		t.Errorf("queue = %+v, want the bucket back with its new failure", got)
	}
}

// assertStat compares a wire aggregate field by field, so a failure names the
// column rather than the struct.
func assertStat(t *testing.T, got, want panel.Stat) {
	t.Helper()
	if got.MonClientID != want.MonClientID || got.InboundKind != want.InboundKind ||
		got.InboundID != want.InboundID || got.Path != want.Path || got.BucketStart != want.BucketStart {
		t.Errorf("key = %s %s:%d:%s bucket %d, want %s %s:%d:%s bucket %d",
			got.MonClientID, got.InboundKind, got.InboundID, got.Path, got.BucketStart,
			want.MonClientID, want.InboundKind, want.InboundID, want.Path, want.BucketStart)
	}
	if got.NOk != want.NOk || got.NFail != want.NFail {
		t.Errorf("nOk/nFail = %d/%d, want %d/%d", got.NOk, got.NFail, want.NOk, want.NFail)
	}
	wantMS(t, "latencyMinMs", got.LatencyMinMS, want.LatencyMinMS)
	wantMS(t, "latencyAvgMs", got.LatencyAvgMS, want.LatencyAvgMS)
	wantMS(t, "latencyMaxMs", got.LatencyMaxMS, want.LatencyMaxMS)
	wantMS(t, "handshakeMs", got.HandshakeMS, want.HandshakeMS)
	if got.BucketStart%stats.WindowMS != 0 {
		t.Errorf("bucketStart %d is not a multiple of %d", got.BucketStart, stats.WindowMS)
	}
}
