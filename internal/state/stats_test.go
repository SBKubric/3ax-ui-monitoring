package state

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
	"github.com/SBKubric/3ax-ui-monitoring/internal/panel"
	"github.com/SBKubric/3ax-ui-monitoring/internal/panel/paneltest"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
)

// statsFixture is one Buckets over a real temp-file store, a fake clock and
// a paneltest stub reached through the real HTTP client — the combination
// docs/agents/testing.md asks for. The client's retry wait is stubbed out so
// a 5xx test does not spend seven seconds observing the 1→2→4s schedule.
type statsFixture struct {
	t    *testing.T
	b    *Buckets
	st   *store.Store
	clk  *clock.Fake
	stub *paneltest.Stub
	cl   panel.Client
}

func newStatsFixture(t *testing.T) *statsFixture {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	clk := clock.NewFake(baseTime)
	stub := paneltest.NewStub(t)
	cl := panel.NewHTTPClient(stub.URL(), stub.Token(), clk,
		panel.WithSleeper(func(context.Context, time.Duration) error { return nil }))
	return &statsFixture{t: t, b: NewBuckets(st, clk), st: st, clk: clk, stub: stub, cl: cl}
}

// record calls Record on f.st.DB directly, which gorm auto-commits as its
// own single-statement-equivalent transaction — the same all-or-nothing
// semantics a real heartbeat's tx gives it, just without a caller
// transaction to nest inside in tests that do not care about that seam.
func (f *statsFixture) record(cycles ...Cycle) {
	f.t.Helper()
	if err := f.b.Record(context.Background(), f.st.DB, "ams-1", cycles); err != nil {
		f.t.Fatalf("Record: %v", err)
	}
}

func (f *statsFixture) flush() error {
	return f.b.Flush(context.Background(), f.cl)
}

func (f *statsFixture) mustFlush() {
	f.t.Helper()
	if err := f.flush(); err != nil {
		f.t.Fatalf("Flush: %v", err)
	}
}

// rows returns every stats bucket in key order, so a test can assert the
// whole table rather than the one row it expected to find.
func (f *statsFixture) rows() []store.StatsBucket {
	f.t.Helper()
	var out []store.StatsBucket
	if err := f.st.DB.Order("bucket_start, inbound_kind, inbound_id, path").Find(&out).Error; err != nil {
		f.t.Fatalf("read stats_buckets: %v", err)
	}
	return out
}

func atMs(t time.Time) int64 { return clock.Ms(t) }

func statMs(v int64) *int64 { return &v }

// statOK is a successful xray probe on the proxy path with a tlsMs.
func statOK(tlsMs int64) Result {
	return Result{InboundKind: store.InboundKindXray, InboundID: 12, Path: store.PathProxy, Ok: true, TlsMs: statMs(tlsMs)}
}

// statFail is the same target failing.
func statFail() Result {
	r := statOK(0)
	r.Ok = false
	r.TlsMs = nil
	return r
}

func statAwg(ok bool, handshake *int64) Result {
	return Result{InboundKind: store.InboundKindAwg, InboundID: 0, Path: store.PathDirect, Ok: ok, HandshakeMs: handshake}
}

// TestRecord_SplitsResultsIntoBucketsAndKeys is spec §7.4's basic layout:
// one row per (key, bucketStart), counts and latency from the results that
// fell into it, and a cycle on the far side of a five-minute boundary in a
// bucket of its own.
func TestRecord_SplitsResultsIntoBucketsAndKeys(t *testing.T) {
	f := newStatsFixture(t)

	f.record(
		Cycle{Seq: 1, Ts: atMs(baseTime), Results: []Result{statOK(40), statAwg(true, statMs(7))}},
		Cycle{Seq: 2, Ts: atMs(baseTime.Add(2 * time.Minute)), Results: []Result{statOK(60), statFail()}},
		// 5 minutes on: the next window, so a second row for the same key.
		Cycle{Seq: 3, Ts: atMs(baseTime.Add(5 * time.Minute)), Results: []Result{statOK(100)}},
	)

	rows := f.rows()
	if len(rows) != 3 {
		t.Fatalf("rows = %d (%+v), want 3: two keys in the first window plus one in the second", len(rows), rows)
	}

	// Ordered by (bucket_start, inbound_kind, inbound_id, path): "awg"
	// sorts before "xray" inside the first window.
	awg, xray := rows[0], rows[1]
	if awg.InboundKind != store.InboundKindAwg || xray.InboundKind != store.InboundKindXray {
		t.Fatalf("rows = %+v, want the awg and the xray bucket of the first window first", rows)
	}

	if xray.BucketStart != atMs(baseTime) || xray.NOk != 2 || xray.NFail != 1 {
		t.Fatalf("xray bucket = %+v, want bucketStart %d, nOk 2, nFail 1", xray, atMs(baseTime))
	}
	if xray.LatMin == nil || *xray.LatMin != 40 || xray.LatMax == nil || *xray.LatMax != 60 ||
		xray.LatAvg == nil || *xray.LatAvg != 50 {
		t.Fatalf("xray latency = %v/%v/%v, want 40/50/60", xray.LatMin, xray.LatAvg, xray.LatMax)
	}
	if awg.NOk != 1 || awg.HandshakeMs == nil || *awg.HandshakeMs != 7 {
		t.Fatalf("awg bucket = %+v, want nOk 1 and handshakeMs 7", awg)
	}

	second := rows[2]
	if second.BucketStart != atMs(baseTime.Add(5*time.Minute)) || second.NOk != 1 || second.NFail != 0 {
		t.Fatalf("second window = %+v, want its own bucket with nOk 1", second)
	}
}

// TestRecord_RolledBackTransactionLeavesNoRows is the seam Record now takes
// tx for (Engine.Heartbeat, internal/state/engine.go): the bucket writes
// must live or die with the caller's transaction, not with Record's own
// commit, because they share the ack that lets the mon-client forget these
// cycles. A caller that rolls back after Record returns nil must therefore
// find nothing written.
func TestRecord_RolledBackTransactionLeavesNoRows(t *testing.T) {
	f := newStatsFixture(t)

	err := f.st.DB.Transaction(func(tx *gorm.DB) error {
		if err := f.b.Record(context.Background(), tx, "ams-1",
			[]Cycle{{Seq: 1, Ts: atMs(baseTime), Results: []Result{statOK(40)}}}); err != nil {
			t.Fatalf("Record: %v", err)
		}
		return errors.New("caller decided to roll back")
	})
	if err == nil {
		t.Fatalf("Transaction returned nil, want the rollback error to surface")
	}

	if rows := f.rows(); len(rows) != 0 {
		t.Fatalf("rows = %+v, want none: the transaction that wrote them was rolled back", rows)
	}
}

// TestRecord_UnverifiedFailureIsAGap is spec §7.4's rule that an unverified
// cycle's failure says nothing — the probe's own destination is mon-server,
// so "the tunnel is down" and "mon-server was unreachable" look identical —
// while its successes are proof the tunnel worked and do count.
func TestRecord_UnverifiedFailureIsAGap(t *testing.T) {
	f := newStatsFixture(t)

	f.record(
		Cycle{Seq: 1, Ts: atMs(baseTime), Results: []Result{statOK(40)}},
		Cycle{Seq: 2, Ts: atMs(baseTime), Unverified: true, Results: []Result{statFail()}},
		Cycle{Seq: 3, Ts: atMs(baseTime), Unverified: true, Results: []Result{statOK(80)}},
	)

	rows := f.rows()
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
	got := rows[0]
	if got.NFail != 0 {
		t.Fatalf("nFail = %d, want 0: an unverified failure is a gap, not a failure", got.NFail)
	}
	if got.NOk != 2 {
		t.Fatalf("nOk = %d, want 2: an unverified success still proves the tunnel worked", got.NOk)
	}
	if got.LatAvg == nil || *got.LatAvg != 60 || got.LatMax == nil || *got.LatMax != 80 {
		t.Fatalf("latency = %v/%v, want avg 60 and max 80 including the unverified success", got.LatAvg, got.LatMax)
	}
}

// TestRecord_SuccessWithoutLatency checks the split spec §7.4 draws between
// the two counters: latency is measured over tlsMs of successful probes, so
// a success that carried no measurement is still a success (nOk) but must
// not be allowed to pull the average toward zero.
func TestRecord_SuccessWithoutLatency(t *testing.T) {
	f := newStatsFixture(t)

	noLat := statOK(0)
	noLat.TlsMs = nil
	f.record(Cycle{Seq: 1, Ts: atMs(baseTime), Results: []Result{statOK(50), noLat}})

	got := f.rows()[0]
	if got.NOk != 2 {
		t.Fatalf("nOk = %d, want 2", got.NOk)
	}
	if got.LatMin == nil || *got.LatMin != 50 || got.LatAvg == nil || *got.LatAvg != 50 || got.LatMax == nil || *got.LatMax != 50 {
		t.Fatalf("latency = %v/%v/%v, want 50/50/50 from the one measured probe", got.LatMin, got.LatAvg, got.LatMax)
	}
	if got.LatN != 1 {
		t.Fatalf("latN = %d, want 1: only the measured probe counts as a sample", got.LatN)
	}
}

// TestRecord_HandshakeIsAwgOnlyAndLatest is spec §7.4's handshake_ms rule:
// only AWG carries one, it is the value from the latest successful cycle
// folded into the bucket, and a bucket with no successes has none at all.
func TestRecord_HandshakeIsAwgOnlyAndLatest(t *testing.T) {
	f := newStatsFixture(t)

	f.record(
		Cycle{Seq: 1, Ts: atMs(baseTime), Results: []Result{statAwg(true, statMs(3)), statOK(40)}},
		Cycle{Seq: 2, Ts: atMs(baseTime), Results: []Result{statAwg(true, statMs(9))}},
		// A later failure must not overwrite the last successful cycle's value.
		Cycle{Seq: 3, Ts: atMs(baseTime), Results: []Result{statAwg(false, statMs(999))}},
	)

	for _, row := range f.rows() {
		switch row.InboundKind {
		case store.InboundKindAwg:
			if row.HandshakeMs == nil || *row.HandshakeMs != 9 {
				t.Fatalf("awg handshakeMs = %v, want 9 (the latest successful cycle)", row.HandshakeMs)
			}
		case store.InboundKindXray:
			if row.HandshakeMs != nil {
				t.Fatalf("xray handshakeMs = %v, want nil: handshake is AWG-only", row.HandshakeMs)
			}
		}
	}

	// A bucket with nothing but failures has n_ok = 0, so every latency and
	// the handshake stay NULL (contract §4.7).
	g := newStatsFixture(t)
	g.record(Cycle{Seq: 1, Ts: atMs(baseTime), Results: []Result{statAwg(false, statMs(5)), statFail()}})
	for _, row := range g.rows() {
		if row.NOk != 0 || row.LatMin != nil || row.LatAvg != nil || row.LatMax != nil || row.HandshakeMs != nil {
			t.Fatalf("all-failure bucket = %+v, want nOk 0 with NULL latency and handshake", row)
		}
	}
}

// TestFlush_OnlyClosedBuckets checks spec §7.4's closing rule: a bucket is
// sent one minute after its window ends, so a window that is merely over is
// still open and stays in the table.
func TestFlush_OnlyClosedBuckets(t *testing.T) {
	f := newStatsFixture(t)
	f.record(
		Cycle{Seq: 1, Ts: atMs(baseTime), Results: []Result{statOK(40)}},
		Cycle{Seq: 2, Ts: atMs(baseTime.Add(5 * time.Minute)), Results: []Result{statOK(50)}},
	)

	// 5 min + 1 min after the first window's start: the first bucket has
	// closed, the second one's window has not even ended.
	f.clk.Advance(6 * time.Minute)
	f.mustFlush()

	sent := f.stub.Stats()
	if len(sent) != 1 {
		t.Fatalf("sent %d buckets (%+v), want only the closed one", len(sent), sent)
	}
	if sent[0].BucketStart != atMs(baseTime) || sent[0].NOk != 1 {
		t.Fatalf("sent = %+v, want the first window", sent[0])
	}
	for _, row := range f.rows() {
		if row.BucketStart == atMs(baseTime) && row.SentAt == nil {
			t.Fatal("the closed bucket was sent but sent_at is still NULL")
		}
		if row.BucketStart != atMs(baseTime) && row.SentAt != nil {
			t.Fatal("the still-open bucket was marked sent")
		}
	}

	// One minute after its own window ends, the second bucket goes too.
	f.clk.Advance(5 * time.Minute)
	f.mustFlush()
	if len(f.stub.Stats()) != 2 {
		t.Fatalf("sent %d buckets, want both once the second window closed", len(f.stub.Stats()))
	}
}

// TestFlush_PayloadMapping checks the wire form of contract §4.7: the row's
// aggregates become latencyMinMs/AvgMs/MaxMs and handshakeMs on the payload
// the panel actually receives.
func TestFlush_PayloadMapping(t *testing.T) {
	f := newStatsFixture(t)
	f.record(Cycle{Seq: 1, Ts: atMs(baseTime), Results: []Result{
		statAwg(true, statMs(12)),
		statOK(40),
	}})
	f.record(Cycle{Seq: 2, Ts: atMs(baseTime), Results: []Result{statOK(60), statFail()}})

	f.clk.Advance(6 * time.Minute)
	f.mustFlush()

	all := f.stub.Stats()
	var xray, awg *panel.StatPayload
	for i := range all {
		if all[i].InboundKind == store.InboundKindXray {
			xray = &all[i]
		} else {
			awg = &all[i]
		}
	}
	if xray == nil || awg == nil {
		t.Fatalf("stats = %+v, want one xray and one awg payload", all)
	}
	if xray.MonClientId != "ams-1" || xray.InboundId != 12 || xray.Path != store.PathProxy {
		t.Fatalf("xray key = %+v, want the target's own key", xray)
	}
	if xray.NOk != 2 || xray.NFail != 1 {
		t.Fatalf("xray counts = %d/%d, want 2/1", xray.NOk, xray.NFail)
	}
	if xray.LatencyMinMs == nil || *xray.LatencyMinMs != 40 ||
		xray.LatencyAvgMs == nil || *xray.LatencyAvgMs != 50 ||
		xray.LatencyMaxMs == nil || *xray.LatencyMaxMs != 60 {
		t.Fatalf("xray latency = %v/%v/%v, want 40/50/60", xray.LatencyMinMs, xray.LatencyAvgMs, xray.LatencyMaxMs)
	}
	if xray.HandshakeMs != nil {
		t.Fatalf("xray handshakeMs = %v, want null", xray.HandshakeMs)
	}
	if awg.HandshakeMs == nil || *awg.HandshakeMs != 12 {
		t.Fatalf("awg handshakeMs = %v, want 12", awg.HandshakeMs)
	}
}

// TestFlush_ResendsBucketChangedAfterSending is spec §7.4's late-cycle rule:
// a heartbeat that arrives after its bucket was already sent adds to it and
// the bucket goes out again, the panel upserting it by key (contract §4.7).
func TestFlush_ResendsBucketChangedAfterSending(t *testing.T) {
	f := newStatsFixture(t)
	f.record(Cycle{Seq: 1, Ts: atMs(baseTime), Results: []Result{statOK(40)}})
	f.clk.Advance(6 * time.Minute)
	f.mustFlush()

	if got := f.stub.Stats(); len(got) != 1 || got[0].NOk != 1 {
		t.Fatalf("first send = %+v, want one bucket with nOk 1", got)
	}

	// A late heartbeat carrying a cycle that belongs to the already-sent
	// window.
	f.record(Cycle{Seq: 2, Ts: atMs(baseTime.Add(time.Minute)), Results: []Result{statOK(60), statFail()}})
	if row := f.rows()[0]; row.SentAt != nil {
		t.Fatal("new data landed in a sent bucket but sent_at was not cleared, so it would never be resent")
	}

	f.mustFlush()
	got := f.stub.Stats()
	if len(got) != 1 {
		t.Fatalf("stub holds %d rows, want the same key upserted once", len(got))
	}
	if got[0].NOk != 2 || got[0].NFail != 1 || got[0].LatencyAvgMs == nil || *got[0].LatencyAvgMs != 50 {
		t.Fatalf("resent bucket = %+v, want nOk 2, nFail 1, avg 50", got[0])
	}
}

// TestFlush_SplitsAtTheContractLimit checks contract §3's cap of 2000 stats
// per POST: a backlog larger than that goes out as several batches, none of
// them over the limit — the stub answers 413 if one ever is.
func TestFlush_SplitsAtTheContractLimit(t *testing.T) {
	f := newStatsFixture(t)

	total := maxStatsPerBatch + 1
	rows := make([]store.StatsBucket, 0, total)
	for i := range total {
		rows = append(rows, store.StatsBucket{
			MonClientId: "ams-1", InboundKind: store.InboundKindXray, InboundId: i, Path: store.PathProxy,
			BucketStart: atMs(baseTime), NOk: 1,
		})
	}
	if err := f.st.DB.CreateInBatches(&rows, 500).Error; err != nil {
		t.Fatalf("seed buckets: %v", err)
	}

	f.clk.Advance(6 * time.Minute)
	f.mustFlush()

	if got := len(f.stub.Stats()); got != total {
		t.Fatalf("panel received %d buckets, want all %d", got, total)
	}
	posts := 0
	for _, r := range f.stub.Requests() {
		if strings.HasSuffix(r.Path, "/stats") {
			posts++
		}
	}
	if posts != 2 {
		t.Fatalf("POST /stats calls = %d, want 2 for %d rows at a limit of %d", posts, total, maxStatsPerBatch)
	}
	var unsent int64
	if err := f.st.DB.Model(&store.StatsBucket{}).Where("sent_at IS NULL").Count(&unsent).Error; err != nil {
		t.Fatalf("count unsent: %v", err)
	}
	if unsent != 0 {
		t.Fatalf("%d buckets still unsent, want every accepted batch stamped", unsent)
	}
}

// TestFlush_DropsBatchThePanelRejected mirrors the outbox rule of spec §4
// and contract §3: a 4xx means resending would fail identically forever, so
// the batch is dropped — marked sent, so the queue cannot wedge behind it —
// and the flush itself is not an error.
func TestFlush_DropsBatchThePanelRejected(t *testing.T) {
	f := newStatsFixture(t)
	f.record(Cycle{Seq: 1, Ts: atMs(baseTime), Results: []Result{statOK(40)}})
	f.clk.Advance(6 * time.Minute)
	f.stub.FailNextOn("/stats", 1, 400)

	if err := f.flush(); err != nil {
		t.Fatalf("Flush = %v, want nil: a rejected batch is dropped, not retried", err)
	}
	if len(f.stub.Stats()) != 0 {
		t.Fatal("the stub recorded a stat row, but the batch was supposed to be rejected")
	}
	for _, row := range f.rows() {
		if row.SentAt == nil {
			t.Fatal("the rejected batch is still unsent, so every later flush would re-send it forever")
		}
		if !row.Dropped {
			t.Fatal("the rejected batch is marked sent but not dropped, so it reads as delivered")
		}
	}
}

// TestFlush_KeepsBatchThePanelCouldNotTake is the other half of the same
// rule: a 5xx (or a transport failure) is retryable, so the rows stay unsent
// and the error goes back to the poller, which retries next cycle.
func TestFlush_KeepsBatchThePanelCouldNotTake(t *testing.T) {
	f := newStatsFixture(t)
	f.record(Cycle{Seq: 1, Ts: atMs(baseTime), Results: []Result{statOK(40)}})
	f.clk.Advance(6 * time.Minute)
	f.stub.FailNextOn("/stats", 10, 500)

	if err := f.flush(); err == nil {
		t.Fatal("Flush = nil, want the 5xx reported so the poller retries next cycle")
	}
	for _, row := range f.rows() {
		if row.SentAt != nil {
			t.Fatal("sent_at was stamped although the panel never accepted the batch")
		}
	}

	// Next cycle, with the panel healthy again, the same rows go out.
	f.stub.FailNextOn("/stats", 0, 0)
	f.mustFlush()
	if len(f.stub.Stats()) != 1 {
		t.Fatalf("stats = %+v, want the kept bucket delivered on the retry", f.stub.Stats())
	}
}

// TestFlush_NothingToSend checks the quiet path: no closed buckets means no
// request at all, not an empty POST the panel has to answer every minute.
func TestFlush_NothingToSend(t *testing.T) {
	f := newStatsFixture(t)
	f.record(Cycle{Seq: 1, Ts: atMs(baseTime), Results: []Result{statOK(40)}})
	f.mustFlush()
	for _, r := range f.stub.Requests() {
		if strings.HasSuffix(r.Path, "/stats") {
			t.Fatal("POST /stats was called with no closed bucket to send")
		}
	}
}

// TestFlush_RejectedBucketIsDroppedAndTheRestSent pins decision #50 for POST
// /stats: the panel answers each bucket on its own, the accepted ones are
// marked sent, and a rejected one is logged and marked dropped — sent_at
// stamped so no later flush offers it again — while its neighbours in the
// same batch still arrive.
func TestFlush_RejectedBucketIsDroppedAndTheRestSent(t *testing.T) {
	f := newStatsFixture(t)
	bad := statOK(40)
	bad.Path = "nowhere" // outside the contract's path grammar
	f.record(Cycle{Seq: 1, Ts: atMs(baseTime), Results: []Result{statOK(40), bad}})
	f.clk.Advance(6 * time.Minute)

	f.mustFlush()

	if got := f.stub.Stats(); len(got) != 1 || got[0].Path != store.PathProxy {
		t.Fatalf("panel holds %+v, want only the valid proxy bucket", got)
	}
	for _, row := range f.rows() {
		if row.SentAt == nil {
			t.Fatalf("bucket %s is still unsent after the panel answered for it", row.Path)
		}
		if want := row.Path == "nowhere"; row.Dropped != want {
			t.Fatalf("bucket %s dropped = %v, want %v", row.Path, row.Dropped, want)
		}
	}

	f.mustFlush()
	if n := len(f.stub.RejectedStats()); n != 1 {
		t.Fatalf("panel saw %d rejections, want exactly 1: a dropped bucket is never retried", n)
	}

	// New data for the window reopens it like any other sent bucket
	// (spec §7.4): the drop was about the old content, not the key.
	f.record(Cycle{Seq: 2, Ts: atMs(baseTime), Results: []Result{bad}})
	for _, row := range f.rows() {
		if row.Path == "nowhere" && (row.SentAt != nil || row.Dropped) {
			t.Fatalf("bucket with new data: sent_at=%v dropped=%v, want it queued again", row.SentAt, row.Dropped)
		}
	}
}

// TestFlush_EmptyAnswerMarksTheBatchSent covers the old panel for POST
// /stats: a bare 200 with no body is "all accepted".
func TestFlush_EmptyAnswerMarksTheBatchSent(t *testing.T) {
	f := newStatsFixture(t)
	f.stub.SetLegacyAnswers(true)
	f.record(Cycle{Seq: 1, Ts: atMs(baseTime), Results: []Result{statOK(40)}})
	f.clk.Advance(6 * time.Minute)

	f.mustFlush()

	for _, row := range f.rows() {
		if row.SentAt == nil || row.Dropped {
			t.Fatalf("bucket sent_at=%v dropped=%v, want sent and not dropped", row.SentAt, row.Dropped)
		}
	}
}
