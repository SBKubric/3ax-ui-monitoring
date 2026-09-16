package stats_test

import (
	"testing"

	"github.com/SBKubric/3ax-ui-monitoring/internal/state"
	"github.com/SBKubric/3ax-ui-monitoring/internal/stats"
)

// TestRecordLatency covers lat_min/lat_avg/lat_max of spec §7.4: the tlsMs of
// the successful probes, NULL when there were none.
//
// The interesting case is the average. It is one integer column, so folding a
// new sample into the stored average — (avg × n + sample) / (n + 1) — drifts;
// the recorder keeps the exact sum behind the bucket instead, and the case
// "a late cycle folds into the exact average" is the one a naive
// implementation gets wrong.
func TestRecordLatency(t *testing.T) {
	cases := []struct {
		name                    string
		cycles                  []cycle
		wantOk                  int
		wantMin, wantAvg, wantM *int64
	}{
		{
			name: "minimum, average and maximum over several cycles",
			cycles: []cycle{
				{ts: testOrigin + 1_000, results: []state.Result{res(xray, 12, proxy, true, p(41), nil)}},
				{ts: testOrigin + 61_000, results: []state.Result{res(xray, 12, proxy, true, p(47), nil)}},
				{ts: testOrigin + 121_000, results: []state.Result{res(xray, 12, proxy, true, p(58), nil)}},
			},
			// (41 + 47 + 58) / 3 = 48.67, rounded to 49.
			wantOk: 3, wantMin: p(41), wantAvg: p(49), wantM: p(58),
		},
		{
			name: "a late cycle folds into the exact average",
			cycles: []cycle{
				{ts: testOrigin + 1_000, results: []state.Result{res(xray, 12, proxy, true, p(41), nil)}},
				{ts: testOrigin + 61_000, results: []state.Result{res(xray, 12, proxy, true, p(42), nil)}},
				// Resent an hour later, long after the window closed. The
				// stored average is 42 (83/2 rounded up); folding 41 into
				// that average gives 42, folding it into the exact sum gives
				// 124/3 = 41.3, which rounds to 41.
				{ts: testOrigin + 121_000, results: []state.Result{res(xray, 12, proxy, true, p(41), nil)}},
			},
			wantOk: 3, wantMin: p(41), wantAvg: p(41), wantM: p(42),
		},
		{
			name: "no successes leaves every latency NULL",
			cycles: []cycle{
				{ts: testOrigin + 1_000, results: []state.Result{res(xray, 12, proxy, false, nil, nil)}},
				{ts: testOrigin + 61_000, results: []state.Result{res(xray, 12, proxy, false, nil, nil)}},
			},
			wantOk: 0, wantMin: nil, wantAvg: nil, wantM: nil,
		},
		{
			name: "a success without a tlsMs counts towards n_ok only",
			cycles: []cycle{
				{ts: testOrigin + 1_000, results: []state.Result{res(xray, 12, proxy, true, nil, nil)}},
			},
			wantOk: 1, wantMin: nil, wantAvg: nil, wantM: nil,
		},
		{
			name: "the average covers the successes that reported a tlsMs",
			cycles: []cycle{
				{ts: testOrigin + 1_000, results: []state.Result{res(xray, 12, proxy, true, p(41), nil)}},
				{ts: testOrigin + 61_000, results: []state.Result{res(xray, 12, proxy, true, nil, nil)}},
			},
			wantOk: 2, wantMin: p(41), wantAvg: p(41), wantM: p(41),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, st, _ := newRecorder(t)
			record(t, r, tc.cycles...)

			row := onlyBucket(t, st)
			if row.NOk != tc.wantOk {
				t.Errorf("nOk = %d, want %d", row.NOk, tc.wantOk)
			}
			wantMS(t, "lat_min", row.LatMin, tc.wantMin)
			wantMS(t, "lat_avg", row.LatAvg, tc.wantAvg)
			wantMS(t, "lat_max", row.LatMax, tc.wantM)
		})
	}
}

// TestRecordLatencyAfterARestart pins the one case the schema of §3 cannot
// carry: a bucket this process has never folded into has no exact sum to fold
// with, so the recorder reseeds it from lat_avg × n_ok. The figure that comes
// out is the rounded one, and the test says so rather than pretending
// otherwise.
func TestRecordLatencyAfterARestart(t *testing.T) {
	r, st, clk := newRecorder(t)
	record(t, r,
		cycle{ts: testOrigin + 1_000, results: []state.Result{res(xray, 12, proxy, true, p(41), nil)}},
		cycle{ts: testOrigin + 61_000, results: []state.Result{res(xray, 12, proxy, true, p(42), nil)}},
	)
	if got := onlyBucket(t, st); got.LatAvg == nil || *got.LatAvg != 42 {
		t.Fatalf("lat_avg = %s, want the rounded 42 of 83/2", show(got.LatAvg))
	}

	// A second recorder over the same database is what a restart looks like.
	fresh := stats.New(st, clk, nil)
	record(t, fresh, cycle{ts: testOrigin + 121_000, results: []state.Result{res(xray, 12, proxy, true, p(41), nil)}})

	row := onlyBucket(t, st)
	if row.NOk != 3 {
		t.Errorf("nOk = %d, want 3", row.NOk)
	}
	if row.LatAvg == nil || *row.LatAvg != 42 {
		t.Errorf("lat_avg = %s, want 42: a reseeded bucket folds from the stored average", show(row.LatAvg))
	}
}

// TestRecordHandshake is the handshake_ms rule of spec §7.4: the value of the
// last successful cycle of the bucket, and only for AmneziaWG.
func TestRecordHandshake(t *testing.T) {
	cases := []struct {
		name   string
		kind   string
		id     int64
		cycles []cycle
		want   *int64
	}{
		{
			name: "the last successful cycle wins", kind: awg, id: 0,
			cycles: []cycle{
				{ts: testOrigin + 1_000, results: []state.Result{res(awg, 0, direct, true, nil, p(120))}},
				{ts: testOrigin + 61_000, results: []state.Result{res(awg, 0, direct, true, nil, p(95))}},
			},
			want: p(95),
		},
		{
			name: "a later failure leaves it alone", kind: awg, id: 0,
			cycles: []cycle{
				{ts: testOrigin + 1_000, results: []state.Result{res(awg, 0, direct, true, nil, p(95))}},
				{ts: testOrigin + 61_000, results: []state.Result{res(awg, 0, direct, false, nil, nil)}},
			},
			want: p(95),
		},
		{
			name: "a cycle that arrives late does not pass for the last one", kind: awg, id: 0,
			cycles: []cycle{
				{ts: testOrigin + 61_000, results: []state.Result{res(awg, 0, direct, true, nil, p(95))}},
				{ts: testOrigin + 1_000, results: []state.Result{res(awg, 0, direct, true, nil, p(200))}},
			},
			want: p(95),
		},
		{
			name: "xray never carries one", kind: xray, id: 12,
			cycles: []cycle{
				{ts: testOrigin + 1_000, results: []state.Result{res(xray, 12, proxy, true, p(41), p(120))}},
			},
			want: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, st, _ := newRecorder(t)
			record(t, r, tc.cycles...)

			row := onlyBucket(t, st)
			if row.InboundKind != tc.kind || row.InboundID != tc.id {
				t.Fatalf("bucket is %s:%d, want %s:%d", row.InboundKind, row.InboundID, tc.kind, tc.id)
			}
			wantMS(t, "handshake_ms", row.HandshakeMs, tc.want)
		})
	}
}

// TestRecordKeepsTargetsApart makes sure the bucket key is the whole key: two
// paths of one inbound, and two inbound kinds, never share a row.
func TestRecordKeepsTargetsApart(t *testing.T) {
	r, st, _ := newRecorder(t)
	record(t, r, cycle{ts: testOrigin + 1_000, results: []state.Result{
		res(xray, 12, proxy, true, p(41), nil),
		res(xray, 12, direct, true, p(47), nil),
		res(xray, 13, proxy, false, nil, nil),
		res(awg, 0, direct, true, nil, p(95)),
	}})

	rows := buckets(t, st)
	if len(rows) != 4 {
		t.Fatalf("got %d buckets, want one per target: %+v", len(rows), rows)
	}
	for _, row := range rows {
		if row.MonClientID != clientID {
			t.Errorf("bucket of %q, want %q", row.MonClientID, clientID)
		}
		if row.SentAt != nil {
			t.Errorf("a fresh bucket is already marked sent: %+v", row)
		}
	}
}

// TestClosingRule is the "one minute after the end of the window" of spec
// §7.4, as arithmetic.
func TestClosingRule(t *testing.T) {
	bucket := testOrigin
	cases := []struct {
		name string
		now  int64
		want bool
	}{
		{"inside the window", bucket + 1, false},
		{"the window has just ended", bucket + stats.WindowMS, false},
		{"one millisecond before the delay is up", bucket + stats.WindowMS + stats.CloseDelayMS - 1, false},
		{"one minute after the window", bucket + stats.WindowMS + stats.CloseDelayMS, true},
		{"long after", bucket + 3*stats.WindowMS, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := stats.IsClosed(bucket, tc.now); got != tc.want {
				t.Errorf("IsClosed(%d, %d) = %v, want %v", bucket, tc.now, got, tc.want)
			}
		})
	}
	if got := stats.ClosesAt(bucket); got != bucket+stats.WindowMS+stats.CloseDelayMS {
		t.Errorf("ClosesAt = %d, want %d", got, bucket+stats.WindowMS+stats.CloseDelayMS)
	}
	if got := stats.End(bucket); got != bucket+stats.WindowMS {
		t.Errorf("End = %d, want %d", got, bucket+stats.WindowMS)
	}
}

// compile-time reminder that the recorder is the sink the state machine
// expects (spec §7.1 step 4).
var _ state.StatsSink = (*stats.Recorder)(nil)
