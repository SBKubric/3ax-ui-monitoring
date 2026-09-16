package stats_test

import (
	"context"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
	"github.com/SBKubric/3ax-ui-monitoring/internal/state"
	"github.com/SBKubric/3ax-ui-monitoring/internal/stats"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
)

// testOrigin is a five-minute boundary: 1772884800000 = 5909616 × 300000. The
// tests place everything relative to it, so a window boundary is an exact
// expression rather than a magic number.
const testOrigin int64 = 1_772_884_800_000

const (
	clientID = "ams-1"
	xray     = store.InboundKindXray
	awg      = store.InboundKindAWG
	proxy    = store.PathProxy
	direct   = store.PathDirect
)

func newRecorder(t *testing.T) (*stats.Recorder, *store.Store, *clock.Fake) {
	t.Helper()
	clk := clock.NewFake(clock.FromMS(testOrigin))
	st, err := store.Open(filepath.Join(t.TempDir(), "mon-server.db"), nil, store.WithClock(clk))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return stats.New(st, clk, nil), st, clk
}

// p is the pointer form every nullable millisecond field takes.
func p(v int64) *int64 { return &v }

// res builds one probe result.
func res(kind string, id int64, path string, ok bool, tls, handshake *int64) state.Result {
	r := state.Result{InboundKind: kind, InboundID: id, Path: path, OK: ok, TLSMS: tls, HandshakeMS: handshake}
	if !ok {
		r.Reason = "tcp_timeout"
	}
	return r
}

// cycle is one call to Record in a table-driven case.
type cycle struct {
	ts         int64
	unverified bool
	results    []state.Result
}

// record plays a list of cycles through the recorder.
func record(t *testing.T, r *stats.Recorder, cycles ...cycle) {
	t.Helper()
	for i, c := range cycles {
		if err := r.Record(context.Background(), clientID, c.ts, c.results, c.unverified); err != nil {
			t.Fatalf("record cycle %d: %v", i, err)
		}
	}
}

func buckets(t *testing.T, st *store.Store) []store.StatsBucket {
	t.Helper()
	var rows []store.StatsBucket
	if err := st.DB().Order("bucket_start asc, inbound_kind asc, inbound_id asc, path asc").Find(&rows).Error; err != nil {
		t.Fatalf("read buckets: %v", err)
	}
	return rows
}

func onlyBucket(t *testing.T, st *store.Store) store.StatsBucket {
	t.Helper()
	rows := buckets(t, st)
	if len(rows) != 1 {
		t.Fatalf("got %d buckets, want exactly one: %+v", len(rows), rows)
	}
	return rows[0]
}

// wantMS compares a nullable millisecond column against an expected value.
func wantMS(t *testing.T, name string, got, want *int64) {
	t.Helper()
	switch {
	case got == nil && want == nil:
	case got == nil || want == nil:
		t.Errorf("%s = %s, want %s", name, show(got), show(want))
	case *got != *want:
		t.Errorf("%s = %d, want %d", name, *got, *want)
	}
}

// show renders a nullable column for a failure message.
func show(v *int64) string {
	if v == nil {
		return "NULL"
	}
	return strconv.FormatInt(*v, 10)
}

// TestStartPlacesATimestampInItsWindow covers the bucket key of spec §7.4:
// bucketStart = ts − ts % 300000, and a timestamp exactly on a boundary opens
// the later window.
func TestStartPlacesATimestampInItsWindow(t *testing.T) {
	cases := []struct {
		name string
		ts   int64
		want int64
	}{
		{"a boundary opens the later window", testOrigin, testOrigin},
		{"one millisecond in", testOrigin + 1, testOrigin},
		{"the middle of the window", testOrigin + 150_000, testOrigin},
		{"the last millisecond", testOrigin + stats.WindowMS - 1, testOrigin},
		{"the next boundary", testOrigin + stats.WindowMS, testOrigin + stats.WindowMS},
		{"one millisecond before", testOrigin - 1, testOrigin - stats.WindowMS},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := stats.Start(tc.ts); got != tc.want {
				t.Errorf("Start(%d) = %d, want %d", tc.ts, got, tc.want)
			}
			if got := stats.Start(tc.ts) % stats.WindowMS; got != 0 {
				t.Errorf("bucketStart %d is not a multiple of the window", stats.Start(tc.ts))
			}
		})
	}
}

// TestRecordBucketsResultsByCycleTimestamp is the same rule through Record:
// the cycle's own timestamp decides the bucket, not the recorder's clock, so a
// cycle that arrives late still lands in the window it happened in.
func TestRecordBucketsResultsByCycleTimestamp(t *testing.T) {
	cases := []struct {
		name string
		ts   int64
		want int64
	}{
		{"inside the live window", testOrigin + 120_000, testOrigin},
		{"exactly on the next boundary", testOrigin + stats.WindowMS, testOrigin + stats.WindowMS},
		{"the last millisecond of a window", testOrigin + stats.WindowMS - 1, testOrigin},
		{"an hour late", testOrigin - 60*60*1000 + 7_000, testOrigin - 60*60*1000},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, st, clk := newRecorder(t)
			// The recorder's own clock is well past every cycle, to prove it
			// takes no part in the bucketing.
			clk.Set(clock.FromMS(testOrigin + 2*stats.WindowMS))
			record(t, r, cycle{ts: tc.ts, results: []state.Result{res(xray, 12, proxy, true, p(41), nil)}})

			row := onlyBucket(t, st)
			if row.BucketStart != tc.want {
				t.Errorf("bucketStart = %d, want %d", row.BucketStart, tc.want)
			}
			if row.NOk != 1 {
				t.Errorf("nOk = %d, want 1", row.NOk)
			}
		})
	}
}

// TestRecordAccumulatesWithinOneWindow is spec §7.4's n_ok and n_fail: every
// cycle of the window folds into the same row, one row per target.
func TestRecordAccumulatesWithinOneWindow(t *testing.T) {
	r, st, _ := newRecorder(t)
	record(t, r,
		cycle{ts: testOrigin + 1_000, results: []state.Result{
			res(xray, 12, proxy, true, p(41), nil),
			res(xray, 12, direct, false, nil, nil),
		}},
		cycle{ts: testOrigin + 61_000, results: []state.Result{
			res(xray, 12, proxy, false, nil, nil),
			res(xray, 12, direct, false, nil, nil),
		}},
		cycle{ts: testOrigin + 121_000, results: []state.Result{
			res(xray, 12, proxy, true, p(47), nil),
			res(xray, 12, direct, true, p(58), nil),
		}},
	)

	rows := buckets(t, st)
	if len(rows) != 2 {
		t.Fatalf("got %d buckets, want one per target: %+v", len(rows), rows)
	}
	byPath := map[string]store.StatsBucket{}
	for _, row := range rows {
		if row.BucketStart != testOrigin {
			t.Errorf("bucketStart = %d, want every cycle in %d", row.BucketStart, testOrigin)
		}
		byPath[row.Path] = row
	}
	if got := byPath[proxy]; got.NOk != 2 || got.NFail != 1 {
		t.Errorf("proxy: nOk/nFail = %d/%d, want 2/1", got.NOk, got.NFail)
	}
	if got := byPath[direct]; got.NOk != 1 || got.NFail != 2 {
		t.Errorf("direct: nOk/nFail = %d/%d, want 1/2", got.NOk, got.NFail)
	}
}

// TestRecordUnverifiedFailuresAreAGap is the rule of spec §7.4 and protocol
// §5.3: the probe's destination is mon-server itself, so a failure reported by
// a cycle whose heartbeat was never acknowledged says nothing about the
// target. Its successes are evidence all the same.
func TestRecordUnverifiedFailuresAreAGap(t *testing.T) {
	cases := []struct {
		name          string
		cycles        []cycle
		wantOk        int
		wantFail      int
		wantLatencies bool
	}{
		{
			name: "an unverified failure is not counted",
			cycles: []cycle{
				{ts: testOrigin + 1_000, results: []state.Result{res(xray, 12, proxy, true, p(41), nil)}},
				{ts: testOrigin + 61_000, unverified: true, results: []state.Result{res(xray, 12, proxy, false, nil, nil)}},
			},
			wantOk: 1, wantFail: 0, wantLatencies: true,
		},
		{
			name: "an unverified success is counted, latency included",
			cycles: []cycle{
				{ts: testOrigin + 1_000, results: []state.Result{res(xray, 12, proxy, true, p(41), nil)}},
				{ts: testOrigin + 61_000, unverified: true, results: []state.Result{res(xray, 12, proxy, true, p(47), nil)}},
			},
			wantOk: 2, wantFail: 0, wantLatencies: true,
		},
		{
			name: "a verified failure still counts",
			cycles: []cycle{
				{ts: testOrigin + 1_000, results: []state.Result{res(xray, 12, proxy, true, p(41), nil)}},
				{ts: testOrigin + 61_000, results: []state.Result{res(xray, 12, proxy, false, nil, nil)}},
			},
			wantOk: 1, wantFail: 1, wantLatencies: true,
		},
		{
			name: "a wholly unverified failing cycle writes no bucket at all",
			cycles: []cycle{
				{ts: testOrigin + 1_000, unverified: true, results: []state.Result{res(xray, 12, proxy, false, nil, nil)}},
			},
			wantOk: 0, wantFail: 0, wantLatencies: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, st, _ := newRecorder(t)
			record(t, r, tc.cycles...)

			rows := buckets(t, st)
			if tc.wantOk == 0 && tc.wantFail == 0 {
				if len(rows) != 0 {
					t.Fatalf("got %d buckets, want none: %+v", len(rows), rows)
				}
				return
			}
			if len(rows) != 1 {
				t.Fatalf("got %d buckets, want one: %+v", len(rows), rows)
			}
			if rows[0].NOk != tc.wantOk || rows[0].NFail != tc.wantFail {
				t.Errorf("nOk/nFail = %d/%d, want %d/%d", rows[0].NOk, rows[0].NFail, tc.wantOk, tc.wantFail)
			}
			if got := rows[0].LatAvg != nil; got != tc.wantLatencies {
				t.Errorf("lat_avg present = %v, want %v", got, tc.wantLatencies)
			}
		})
	}
}
