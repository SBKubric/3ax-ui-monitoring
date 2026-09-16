package dispatch_test

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
	"github.com/SBKubric/3ax-ui-monitoring/internal/dispatch"
	"github.com/SBKubric/3ax-ui-monitoring/internal/events"
	"github.com/SBKubric/3ax-ui-monitoring/internal/panel"
	"github.com/SBKubric/3ax-ui-monitoring/internal/paneltest"
	"github.com/SBKubric/3ax-ui-monitoring/internal/state"
	"github.com/SBKubric/3ax-ui-monitoring/internal/stats"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
)

// testOrigin is a five-minute boundary, so every bucket in these tests has the
// bucketStart contract §4.7 demands.
const testOrigin int64 = 1_772_884_800_000

const (
	clientID = "ams-1"
	xray     = store.InboundKindXray
	proxy    = store.PathProxy
	direct   = store.PathDirect
)

// harness is one mon-server talking to one stub panel.
type harness struct {
	t      *testing.T
	st     *store.Store
	clk    *clock.Fake
	stub   *paneltest.Stub
	outbox *events.Outbox
	rec    *stats.Recorder
	d      *dispatch.Dispatcher
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	clk := clock.NewFake(clock.FromMS(testOrigin))
	st, err := store.Open(filepath.Join(t.TempDir(), "mon-server.db"), nil, store.WithClock(clk))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	stub := paneltest.NewStub(t)
	client, err := panel.New(panel.Options{
		BaseURL: stub.URL(),
		Token:   paneltest.DefaultToken,
		Clock:   clk,
		// No test waits out the contract's backoff; the retry policy itself
		// is internal/panel's to cover.
		Backoff: func(context.Context, int) error { return nil },
	})
	if err != nil {
		t.Fatalf("panel client: %v", err)
	}
	rec := stats.New(st, clk, nil)
	d, err := dispatch.New(dispatch.Options{Store: st, Panel: client, Stats: rec, Clock: clk})
	if err != nil {
		t.Fatalf("dispatcher: %v", err)
	}
	return &harness{t: t, st: st, clk: clk, stub: stub, outbox: events.New(st, nil), rec: rec, d: d}
}

// dispatch runs one drain and fails the test on an unexpected error.
func (h *harness) dispatch() int {
	h.t.Helper()
	sent, err := h.d.Dispatch(context.Background())
	if err != nil {
		h.t.Fatalf("dispatch: %v", err)
	}
	return sent
}

// enqueue files target events for the given timestamps, in the order given.
func (h *harness) enqueue(inboundID int64, timestamps ...int64) {
	h.t.Helper()
	evs := make([]panel.Event, 0, len(timestamps))
	for _, ts := range timestamps {
		evs = append(evs, events.Target(ts, clientID, xray, inboundID, proxy,
			panel.TargetUp, panel.TargetDown, panel.ReasonTLSTimeout))
	}
	if err := h.outbox.EnqueueAll(context.Background(), evs); err != nil {
		h.t.Fatalf("enqueue %d events: %v", len(evs), err)
	}
}

// outboxRows reads the queue in delivery order.
func (h *harness) outboxRows() []store.EventOutbox {
	h.t.Helper()
	var rows []store.EventOutbox
	if err := h.st.DB().Order("ts asc, id asc").Find(&rows).Error; err != nil {
		h.t.Fatalf("read outbox: %v", err)
	}
	return rows
}

// unsentEvents counts the rows still waiting.
func (h *harness) unsentEvents() int {
	h.t.Helper()
	n := 0
	for _, row := range h.outboxRows() {
		if row.SentAt == nil {
			n++
		}
	}
	return n
}

// buckets reads the aggregates oldest first.
func (h *harness) buckets() []store.StatsBucket {
	h.t.Helper()
	var rows []store.StatsBucket
	if err := h.st.DB().Order("bucket_start asc, id asc").Find(&rows).Error; err != nil {
		h.t.Fatalf("read buckets: %v", err)
	}
	return rows
}

// recordCycle folds one probe cycle into its bucket.
func (h *harness) recordCycle(ts int64, ok bool, tlsMS int64) {
	h.t.Helper()
	res := state.Result{InboundKind: xray, InboundID: 12, Path: proxy, OK: ok}
	if ok {
		res.TLSMS = &tlsMS
	} else {
		res.Reason = panel.ReasonTCPTimeout
	}
	if err := h.rec.Record(context.Background(), clientID, ts, []state.Result{res}, false); err != nil {
		h.t.Fatalf("record cycle: %v", err)
	}
}

// closeBuckets moves the clock past the closing time of the newest bucket, so
// that everything recorded so far is ready to go out.
func (h *harness) closeBuckets(newest int64) {
	h.t.Helper()
	h.clk.Set(clock.FromMS(stats.ClosesAt(stats.Start(newest))))
}

// batchSizes reports how many items each request to one endpoint carried.
func (h *harness) batchSizes(endpoint string) []int {
	h.t.Helper()
	var sizes []int
	for _, req := range h.stub.Requests() {
		if req.Endpoint != endpoint {
			continue
		}
		var body struct {
			Events []json.RawMessage `json:"events"`
			Stats  []json.RawMessage `json:"stats"`
		}
		if err := json.Unmarshal(req.Body, &body); err != nil {
			h.t.Fatalf("decode %s body: %v", endpoint, err)
		}
		sizes = append(sizes, len(body.Events)+len(body.Stats))
	}
	return sizes
}

// TestDispatchSendsEventsInTimestampOrder is spec §4 step 4: the outbox goes
// out ordered by ts, every event keeping the timestamp it was filed with, and
// sent_at is written only once the panel has answered 200.
func TestDispatchSendsEventsInTimestampOrder(t *testing.T) {
	h := newHarness(t)
	h.enqueue(12, testOrigin+3_000, testOrigin+1_000, testOrigin+2_000)

	at := testOrigin + 30_000
	h.clk.Set(clock.FromMS(at))
	if sent := h.dispatch(); sent != 3 {
		t.Errorf("dispatch reported %d events, want 3", sent)
	}

	got := h.stub.Events()
	if len(got) != 3 {
		t.Fatalf("panel got %d events, want 3", len(got))
	}
	want := []int64{testOrigin + 1_000, testOrigin + 2_000, testOrigin + 3_000}
	for i, ev := range got {
		if ev.TS != want[i] {
			t.Errorf("event %d has ts %d, want %d: the batch is not in ts order", i, ev.TS, want[i])
		}
	}
	for _, row := range h.outboxRows() {
		if row.SentAt == nil || *row.SentAt != at {
			t.Errorf("event %s has sent_at %v, want %d", row.ID, row.SentAt, at)
		}
	}
	if n := h.stub.Count(paneltest.Events); n != 1 {
		t.Errorf("made %d requests to POST /events, want one", n)
	}
}

// TestDispatchEmptyQueueMakesNoRequest keeps the idle cycle silent: nothing
// queued means nothing sent, not an empty batch.
func TestDispatchEmptyQueueMakesNoRequest(t *testing.T) {
	h := newHarness(t)
	if sent := h.dispatch(); sent != 0 {
		t.Errorf("dispatch reported %d events, want 0", sent)
	}
	if n := h.stub.Count(paneltest.Any); n != 0 {
		t.Errorf("made %d requests on an empty queue, want none: %+v", n, h.stub.Requests())
	}
}

// TestDispatchCutsEventBatches is the 1000 event limit of contract §3: a
// backlog larger than one batch goes out in several, and all of it is stamped.
func TestDispatchCutsEventBatches(t *testing.T) {
	h := newHarness(t)
	timestamps := make([]int64, 0, panel.MaxEvents+1)
	for i := range panel.MaxEvents + 1 {
		timestamps = append(timestamps, testOrigin+int64(i))
	}
	h.enqueue(12, timestamps...)

	if sent := h.dispatch(); sent != panel.MaxEvents+1 {
		t.Errorf("dispatch reported %d events, want %d", sent, panel.MaxEvents+1)
	}
	if got, want := h.batchSizes(paneltest.Events), []int{panel.MaxEvents, 1}; !equalInts(got, want) {
		t.Errorf("batch sizes = %v, want %v", got, want)
	}
	if n := h.unsentEvents(); n != 0 {
		t.Errorf("%d events still unsent, want none", n)
	}
}

// TestDispatchCutsStatsBatches is the 2000 aggregate limit of contract §3.
func TestDispatchCutsStatsBatches(t *testing.T) {
	h := newHarness(t)
	total := panel.MaxStats + 1
	rows := make([]store.StatsBucket, 0, total)
	for i := range total {
		rows = append(rows, store.StatsBucket{
			MonClientID: clientID, InboundKind: xray, InboundID: 12, Path: proxy,
			BucketStart: testOrigin - int64(i)*stats.WindowMS,
			NOk:         1, NFail: 0,
			LatMin: ptr(41), LatAvg: ptr(41), LatMax: ptr(41),
		})
	}
	if err := h.st.DB().CreateInBatches(&rows, 200).Error; err != nil {
		t.Fatalf("create buckets: %v", err)
	}
	h.closeBuckets(testOrigin)

	h.dispatch()
	if got, want := h.batchSizes(paneltest.Stats), []int{panel.MaxStats, 1}; !equalInts(got, want) {
		t.Errorf("batch sizes = %v, want %v", got, want)
	}
	for _, row := range h.buckets() {
		if row.SentAt == nil {
			t.Fatalf("bucket %d is still unsent", row.BucketStart)
		}
	}
}

// TestDispatchPanelFailures separates the two ways a request can fail
// (spec §4, §4.1): a 4xx is the panel refusing this batch, which is logged and
// dropped so the queue behind it can move, while a panel that cannot be
// reached ends the drain and hands the failure to the poll loop, which counts
// it towards PANEL_DOWN. Neither ever writes sent_at.
func TestDispatchPanelFailures(t *testing.T) {
	cases := []struct {
		name          string
		failure       paneltest.Failure
		wantErr       bool
		wantStatsSent bool
	}{
		{"a 400 drops the batch", paneltest.InvalidBody("events[0]: bad"), false, true},
		{"a bare 404 drops the batch", paneltest.NotFound(), false, true},
		{"a 413 drops the batch", paneltest.BatchTooLarge(), false, true},
		{"a 500 stops the drain", paneltest.ServerError(), true, false},
		{"a 503 stops the drain", paneltest.Starting(), true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			h.enqueue(12, testOrigin+1_000, testOrigin+2_000)
			h.recordCycle(testOrigin+1_000, true, 41)
			h.closeBuckets(testOrigin)
			h.stub.Fail(paneltest.Events, tc.failure)

			sent, err := h.d.Dispatch(context.Background())
			switch {
			case tc.wantErr && err == nil:
				t.Fatalf("dispatch returned no error, want one the poll loop can count")
			case tc.wantErr && !errors.Is(err, panel.ErrUnavailable):
				t.Fatalf("dispatch error = %v, want one matching ErrUnavailable", err)
			case !tc.wantErr && err != nil:
				t.Fatalf("dispatch: %v", err)
			}
			if sent != 0 {
				t.Errorf("dispatch reported %d events, want 0: none were accepted", sent)
			}
			if n := h.unsentEvents(); n != 2 {
				t.Errorf("%d events unsent, want both: sent_at may only follow a 200", n)
			}

			statsSent := h.stub.Count(paneltest.Stats) > 0
			if statsSent != tc.wantStatsSent {
				t.Errorf("statistics sent = %v, want %v", statsSent, tc.wantStatsSent)
			}
			for _, row := range h.buckets() {
				if got := row.SentAt != nil; got != tc.wantStatsSent {
					t.Errorf("bucket %d sent = %v, want %v", row.BucketStart, got, tc.wantStatsSent)
				}
			}
		})
	}
}

// TestDispatchDuplicatesAndIgnoredAreNotFailures is contract §4.6: the panel
// deduplicates by id and drops what belongs to an inbound it no longer has.
// Both come back inside a 200, so the batch counts as delivered and only the
// accepted number is reported upwards.
func TestDispatchDuplicatesAndIgnoredAreNotFailures(t *testing.T) {
	h := newHarness(t)
	h.stub.SetStrictInbounds(true)
	// Inbound 12 is in the stub's state; 99 is not, so the panel ignores it.
	h.enqueue(12, testOrigin+1_000)
	h.enqueue(99, testOrigin+2_000)

	if sent := h.dispatch(); sent != 1 {
		t.Errorf("dispatch reported %d events, want the one the panel accepted", sent)
	}
	if n := h.unsentEvents(); n != 0 {
		t.Errorf("%d events unsent, want none: an ignored event is delivered, not failed", n)
	}

	// The same event again: the panel calls it a duplicate, which is not an
	// error either and must not leave the row queued.
	rows := h.outboxRows()
	if err := h.st.DB().Model(&store.EventOutbox{}).Where("id = ?", rows[0].ID).
		Update("sent_at", nil).Error; err != nil {
		t.Fatalf("requeue event: %v", err)
	}
	if n := h.unsentEvents(); n != 1 {
		t.Fatalf("%d events queued after requeueing one, want exactly one", n)
	}
	if sent := h.dispatch(); sent != 0 {
		t.Errorf("dispatch reported %d events, want 0: the panel already had it", sent)
	}
	if n := h.unsentEvents(); n != 0 {
		t.Errorf("%d events unsent after a duplicate, want none", n)
	}
	if posted := len(h.stub.Events()); posted != 3 {
		t.Errorf("panel received %d events, want the duplicate to have been posted again", posted)
	}
}

// TestDispatchResendsABucketALateCycleChanged closes the loop with
// internal/stats: a cycle that arrives after its bucket was delivered clears
// sent_at, and the next drain sends the corrected aggregate, which the panel
// upserts (spec §7.4, contract §4.7).
func TestDispatchResendsABucketALateCycleChanged(t *testing.T) {
	h := newHarness(t)
	h.recordCycle(testOrigin+1_000, true, 41)
	h.closeBuckets(testOrigin)
	h.dispatch()

	first := h.stub.Stats()
	if len(first) != 1 || first[0].NOk != 1 {
		t.Fatalf("panel got %+v, want one aggregate with one success", first)
	}

	// The mon-client resends a cycle of the same window an hour later.
	h.recordCycle(testOrigin+61_000, true, 47)
	if got := h.buckets(); len(got) != 1 || got[0].SentAt != nil {
		t.Fatalf("bucket = %+v, want sent_at cleared by the late cycle", got)
	}
	h.dispatch()

	all := h.stub.Stats()
	if len(all) != 2 {
		t.Fatalf("panel got %d aggregates, want the bucket twice", len(all))
	}
	again := all[1]
	if again.BucketStart != testOrigin || again.NOk != 2 {
		t.Errorf("resent aggregate = %+v, want bucket %d with two successes", again, testOrigin)
	}
	if again.LatencyAvgMS == nil || *again.LatencyAvgMS != 44 {
		t.Errorf("resent average = %v, want 44 over 41 and 47", again.LatencyAvgMS)
	}
	if row := h.buckets()[0]; row.SentAt == nil {
		t.Error("the resent bucket is still queued")
	}
}

// TestDispatchReportsWhatThePanelAccepted is the number the "panel back"
// message of spec §4.1 quotes: what the panel took, not what was posted.
func TestDispatchReportsWhatThePanelAccepted(t *testing.T) {
	h := newHarness(t)
	h.stub.SetStrictInbounds(true)
	h.enqueue(12, testOrigin+1_000, testOrigin+2_000)
	h.enqueue(99, testOrigin+3_000)

	sent := h.dispatch()
	if sent != 2 {
		t.Errorf("dispatch reported %d events, want 2 accepted of 3 posted", sent)
	}
	if posted := len(h.stub.Events()); posted != 3 {
		t.Errorf("panel received %d events, want all 3 posted", posted)
	}
}

// TestDispatchWithoutAStatsQueue covers the wiring before the recorder exists:
// events still go out and nothing asks for aggregates.
func TestDispatchWithoutAStatsQueue(t *testing.T) {
	h := newHarness(t)
	d, err := dispatch.New(dispatch.Options{Store: h.st, Panel: mustClient(t, h.stub, h.clk), Clock: h.clk})
	if err != nil {
		t.Fatalf("dispatcher: %v", err)
	}
	h.enqueue(12, testOrigin+1_000)

	sent, err := d.Dispatch(context.Background())
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if sent != 1 {
		t.Errorf("dispatch reported %d events, want 1", sent)
	}
	if n := h.stub.Count(paneltest.Stats); n != 0 {
		t.Errorf("made %d requests to POST /stats without a queue, want none", n)
	}
}

// TestNewRejectsAnIncompleteDispatcher: the two things it cannot work without.
func TestNewRejectsAnIncompleteDispatcher(t *testing.T) {
	h := newHarness(t)
	cases := []struct {
		name string
		opts dispatch.Options
	}{
		{"no store", dispatch.Options{Panel: mustClient(t, h.stub, h.clk)}},
		{"no panel client", dispatch.Options{Store: h.st}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := dispatch.New(tc.opts); !errors.Is(err, dispatch.ErrInvalidOptions) {
				t.Errorf("New error = %v, want ErrInvalidOptions", err)
			}
		})
	}
}

func mustClient(t *testing.T, stub *paneltest.Stub, clk *clock.Fake) *panel.Client {
	t.Helper()
	client, err := panel.New(panel.Options{
		BaseURL: stub.URL(),
		Token:   paneltest.DefaultToken,
		Clock:   clk,
		Backoff: func(context.Context, int) error { return nil },
	})
	if err != nil {
		t.Fatalf("panel client: %v", err)
	}
	return client
}

func ptr(v int64) *int64 { return &v }

func equalInts(got, want []int) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
