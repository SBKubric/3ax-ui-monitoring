package panel_test

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
	"github.com/SBKubric/3ax-ui-monitoring/internal/panel"
	"github.com/SBKubric/3ax-ui-monitoring/internal/panel/paneltest"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
)

// testTime is a fixed instant every test's Fake clock starts at; nothing in
// these tests depends on its value, only on it not moving on its own.
var testTime = time.Date(2025, 9, 13, 12, 0, 0, 0, time.UTC)

// sleepLog is the injected retry Sleeper: it records the delays the client
// asked for and returns immediately, so the 1 → 2 → 4 s schedule of spec §4
// can be asserted in microseconds.
type sleepLog struct {
	mu sync.Mutex
	d  []time.Duration
}

func (s *sleepLog) sleep(_ context.Context, d time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.d = append(s.d, d)
	return nil
}

func (s *sleepLog) delays() []time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]time.Duration(nil), s.d...)
}

func newClient(t *testing.T, s *paneltest.Stub, opts ...panel.Option) (*panel.HTTPClient, *sleepLog) {
	t.Helper()
	log := &sleepLog{}
	all := append([]panel.Option{panel.WithSleeper(log.sleep)}, opts...)
	return panel.NewHTTPClient(s.URL(), s.Token(), clock.NewFake(testTime), all...), log
}

func wantDelays(t *testing.T, got []time.Duration, want ...time.Duration) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("slept %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("slept %v, want %v", got, want)
		}
	}
}

// TestHTTPClient_RetriesOn5xxThenSucceeds checks spec §4's retry policy on
// its happy path: two 500s cost two backoffs of 1 s and 2 s, and the third
// attempt's answer is the one the caller gets.
func TestHTTPClient_RetriesOn5xxThenSucceeds(t *testing.T) {
	s := paneltest.NewStub(t)
	s.SetInbounds([]panel.Inbound{{Kind: "xray", InboundId: 12, Protocol: "vless", Port: 443, Enable: true}})
	c, sleeps := newClient(t, s)

	s.FailNext(2, http.StatusInternalServerError)
	st, err := c.State(context.Background())
	if err != nil {
		t.Fatalf("State: %v", err)
	}
	if st.Revision != s.Revision() {
		t.Fatalf("revision = %q, want %q", st.Revision, s.Revision())
	}
	wantDelays(t, sleeps.delays(), time.Second, 2*time.Second)
	if n := len(s.Requests()); n != 3 {
		t.Fatalf("%d requests, want 3 (two failures plus the success)", n)
	}
}

// TestHTTPClient_DoesNotRetryOn4xx checks the other half of spec §4: a 4xx
// is the panel rejecting the request itself, so it comes straight back as an
// APIError with no retry and no wait, for the caller to drop the batch.
func TestHTTPClient_DoesNotRetryOn4xx(t *testing.T) {
	s := paneltest.NewStub(t)
	c, sleeps := newClient(t, s)

	s.FailNext(1, http.StatusBadRequest)
	_, err := c.PostEvents(context.Background(), []store.EventPayload{{ID: "a"}})

	var apiErr *panel.APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("err = %v (%T), want *panel.APIError", err, err)
	}
	if apiErr.Status != http.StatusBadRequest || apiErr.Code != "invalid_body" {
		t.Fatalf("APIError = %+v, want 400 invalid_body", apiErr)
	}
	if apiErr.Retryable() {
		t.Fatal("a 4xx must not be retryable")
	}
	wantDelays(t, sleeps.delays())
	if n := len(s.Requests()); n != 1 {
		t.Fatalf("%d requests, want exactly 1", n)
	}
}

// TestHTTPClient_GivesUpAfterThreeRetries checks that the schedule is
// finite: four attempts, three waits of 1 s, 2 s and 4 s, and then the
// failure is the caller's problem (spec §4: "не дольше минуты цикла").
func TestHTTPClient_GivesUpAfterThreeRetries(t *testing.T) {
	s := paneltest.NewStub(t)
	c, sleeps := newClient(t, s)

	s.FailNext(4, http.StatusInternalServerError)
	_, err := c.State(context.Background())

	var apiErr *panel.APIError
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusInternalServerError {
		t.Fatalf("err = %v, want a 500 APIError", err)
	}
	if !panel.IsRetryable(err) {
		t.Fatal("a 500 that was retried to exhaustion is still a retryable kind of failure")
	}
	wantDelays(t, sleeps.delays(), time.Second, 2*time.Second, 4*time.Second)
	if n := len(s.Requests()); n != 4 {
		t.Fatalf("%d requests, want 4 (one attempt plus three retries)", n)
	}
}

// TestHTTPClient_RetriesOnNetworkError checks that a connection that dies
// before any status is retried on the same schedule — the panel restarting
// mid-poll must not cost a cycle.
func TestHTTPClient_RetriesOnNetworkError(t *testing.T) {
	s := paneltest.NewStub(t)
	c, sleeps := newClient(t, s)

	s.DropNext(2)
	if _, err := c.State(context.Background()); err != nil {
		t.Fatalf("State: %v", err)
	}
	wantDelays(t, sleeps.delays(), time.Second, 2*time.Second)
}

// TestHTTPClient_TimeoutIsRetriedAndReportedAsTimeout checks spec §4's
// timeout arm: a panel that never answers produces a net.Error with
// Timeout() true after the full retry schedule, which is what the poller
// maps to the http_timeout reason (§4.1).
func TestHTTPClient_TimeoutIsRetriedAndReportedAsTimeout(t *testing.T) {
	s := paneltest.NewStub(t)
	c, sleeps := newClient(t, s, panel.WithTimeout(20*time.Millisecond))

	s.SleepNext(4, 2*time.Second)
	_, err := c.State(context.Background())
	if err == nil {
		t.Fatal("State returned no error against a panel that never answers")
	}
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("err = %v (%T), want a timeout", err, err)
	}
	wantDelays(t, sleeps.delays(), time.Second, 2*time.Second, 4*time.Second)
}

// TestHTTPClient_BareNotFoundIsErrNotFound checks contract §2: the bare 404
// mon-server gets for a wrong token or with monitoring off is its own
// sentinel, not an APIError, because it means something else entirely — and
// it is not retried, since the panel is plainly answering.
func TestHTTPClient_BareNotFoundIsErrNotFound(t *testing.T) {
	s := paneltest.NewStub(t)
	s.SetMonEnabled(false)
	c, sleeps := newClient(t, s)

	_, err := c.State(context.Background())
	if !errors.Is(err, panel.ErrNotFound) {
		t.Fatalf("err = %v, want panel.ErrNotFound", err)
	}
	var apiErr *panel.APIError
	if errors.As(err, &apiErr) {
		t.Fatalf("a bare 404 must not be an APIError, got %+v", apiErr)
	}
	wantDelays(t, sleeps.delays())
	if n := len(s.Requests()); n != 1 {
		t.Fatalf("%d requests, want 1 — a bare 404 is not retried", n)
	}
}

// TestHTTPClient_BadBodyOnA200IsNotRetried checks the PLAUSIBLE finding: a
// 200 whose body is not contract JSON (a captive portal or a stray proxy in
// front of panelUrl) must not be treated as a network error — spec §4
// retries only network/5xx/timeout, and this is none of those.
func TestHTTPClient_BadBodyOnA200IsNotRetried(t *testing.T) {
	s := paneltest.NewStub(t)
	c, sleeps := newClient(t, s)

	s.BadBodyNext(1)
	_, err := c.State(context.Background())
	if !errors.Is(err, panel.ErrBadBody) {
		t.Fatalf("err = %v (%T), want panel.ErrBadBody", err, err)
	}
	if panel.IsRetryable(err) {
		t.Fatal("a bad body on a 200 must not be retryable")
	}
	var ne *net.OpError
	if errors.As(err, &ne) {
		t.Fatalf("err = %v, must not read as a network error", err)
	}
	wantDelays(t, sleeps.delays())
	if n := len(s.Requests()); n != 1 {
		t.Fatalf("%d requests, want exactly 1 — a bad body is not retried", n)
	}
}

// TestHTTPClient_GenuineBodyReadErrorStaysANetError checks the other half of
// the PLAUSIBLE finding: a body that starts decoding and then the connection
// dies mid-read (io.ErrUnexpectedEOF, not a syntax or type error) is still a
// netError, because that really is the connection failing, not the far end
// answering something wrong — and it must still be retried.
func TestHTTPClient_GenuineBodyReadErrorStaysANetError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Mon-Contract", "1")
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Content-Length", "40")
		w.WriteHeader(http.StatusOK)
		// Declares 40 bytes, writes fewer, then the handler returns and the
		// server closes the body early — an incomplete read, not bad JSON.
		_, _ = w.Write([]byte(`{"revision":"abc"`))
	}))
	t.Cleanup(srv.Close)

	c := panel.NewHTTPClient(srv.URL, "t", clock.NewFake(testTime), panel.WithSleeper(func(context.Context, time.Duration) error { return nil }))
	_, err := c.State(context.Background())
	if err == nil {
		t.Fatal("State returned no error for a truncated body")
	}
	if errors.Is(err, panel.ErrBadBody) {
		t.Fatalf("err = %v, a truncated read must not read as ErrBadBody", err)
	}
	if !panel.IsRetryable(err) {
		t.Fatal("a truncated body must stay a retryable netError")
	}
}

// TestHTTPClient_DecodesFreshOnEachRetry checks that a retry does not decode
// on top of whatever an earlier, failed attempt's body partially filled in:
// the first attempt's body sets Revision and then the connection cuts off
// mid-object (a genuine truncated read, io.ErrUnexpectedEOF — a netError,
// which is retried), and the retry's own body never mentions revision at
// all. A client that reused the same *State across attempts would report the
// first attempt's Revision even though nothing in the successful response
// said so.
func TestHTTPClient_DecodesFreshOnEachRetry(t *testing.T) {
	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Mon-Contract", "1")
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		if atomic.AddInt32(&n, 1) == 1 {
			w.Header().Set("Content-Length", "40")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"revision":"stale-from-attempt-one"`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"contract":1}`))
	}))
	t.Cleanup(srv.Close)

	c := panel.NewHTTPClient(srv.URL, "t", clock.NewFake(testTime),
		panel.WithSleeper(func(context.Context, time.Duration) error { return nil }))
	st, err := c.State(context.Background())
	if err != nil {
		t.Fatalf("State: %v", err)
	}
	if st.Revision != "" {
		t.Fatalf("revision = %q, want empty — a stale decode from the failed first attempt leaked into the retry's result", st.Revision)
	}
}

// TestHTTPClient_NotFoundWithBodyIsAPIError checks the other 404 of contract
// §3: an authenticated caller hitting an unknown route gets the error body,
// and the client must keep the two apart — one means "fix the token", the
// other "fix the path".
func TestHTTPClient_NotFoundWithBodyIsAPIError(t *testing.T) {
	s := paneltest.NewStub(t)
	c, _ := newClient(t, s)

	s.FailNext(1, http.StatusConflict)
	_, err := c.ProbeConfigs(context.Background(), "")
	var apiErr *panel.APIError
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusConflict {
		t.Fatalf("err = %v, want a 409 APIError", err)
	}
	if errors.Is(err, panel.ErrNotFound) {
		t.Fatal("a contract error body must not read as the bare 404")
	}
}

// TestHTTPClient_JoinsBasePathAndSendsHeaders checks contract §1 and §2 on
// the wire: the contract path is appended to the panel's webBasePath without
// doubling the slash, and every request carries the bearer and the JSON
// headers.
func TestHTTPClient_JoinsBasePathAndSendsHeaders(t *testing.T) {
	s := paneltest.NewStub(t)
	c, _ := newClient(t, s)

	if _, err := c.ProbeEnsure(context.Background(), []panel.MonClientSnapshot{{Id: "ams-1"}}); err != nil {
		t.Fatalf("ProbeEnsure: %v", err)
	}

	reqs := s.Requests()
	if len(reqs) != 1 {
		t.Fatalf("%d requests, want 1", len(reqs))
	}
	r := reqs[0]
	if r.Path != "/panel/mon/v1/probe/ensure" {
		t.Fatalf("path = %q, want /panel/mon/v1/probe/ensure", r.Path)
	}
	if got := r.Header.Get("Authorization"); got != "Bearer "+s.Token() {
		t.Fatalf("Authorization = %q", got)
	}
	if got := r.Header.Get("Content-Type"); got != "application/json; charset=utf-8" {
		t.Fatalf("Content-Type = %q", got)
	}
	if got := r.Header.Get("Accept"); got != "application/json" {
		t.Fatalf("Accept = %q", got)
	}
	if ensured := s.Ensured(); len(ensured) != 1 || ensured[0][0].Id != "ams-1" {
		t.Fatalf("Ensured() = %+v, want the snapshot that was sent", ensured)
	}
}

// TestHTTPClient_ProbeConfigsPathSelection checks contract §4.4's way of
// naming a path: the proxy path is the absence of the host parameter, not an
// empty one, and the direct path passes the real host through.
func TestHTTPClient_ProbeConfigsPathSelection(t *testing.T) {
	s := paneltest.NewStub(t)
	s.SetOverride(true, "front.example.net")
	sub := "sub-1"
	s.SetProbeSubID(&sub)
	c, _ := newClient(t, s)

	if _, err := c.ProbeConfigs(context.Background(), ""); err != nil {
		t.Fatalf("proxy ProbeConfigs: %v", err)
	}
	if _, err := c.ProbeConfigs(context.Background(), "real.example.net"); err != nil {
		t.Fatalf("direct ProbeConfigs: %v", err)
	}

	reqs := s.Requests()
	if len(reqs) != 2 {
		t.Fatalf("%d requests, want 2", len(reqs))
	}
	if _, present := reqs[0].Query["host"]; present {
		t.Fatalf("proxy request carried host=%q, want no host parameter at all", reqs[0].Query.Get("host"))
	}
	if got := reqs[1].Query.Get("host"); got != "real.example.net" {
		t.Fatalf("direct request host = %q", got)
	}
}

// TestHTTPClient_IgnoresUnknownResponseFields checks contract §1's
// forward-compatibility rule: the panel may add optional fields without
// bumping the version, so a response carrying fields this build has never
// heard of must decode, not fail.
func TestHTTPClient_IgnoresUnknownResponseFields(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Mon-Contract", "1")
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = w.Write([]byte(`{"contract":1,"revision":"abc","somethingNew":{"deep":[1,2]},"inbounds":[{"kind":"xray","inboundId":1,"futureField":true}]}`))
	}))
	t.Cleanup(srv.Close)

	c := panel.NewHTTPClient(srv.URL, "t", clock.NewFake(testTime))
	st, err := c.State(context.Background())
	if err != nil {
		t.Fatalf("State: %v", err)
	}
	if st.Revision != "abc" || len(st.Inbounds) != 1 || st.Inbounds[0].InboundId != 1 {
		t.Fatalf("decoded state = %+v, want the known fields kept", st)
	}
}

// TestHTTPClient_EmptyBatchAnswerMeansAllAccepted pins decision #50's
// compatibility rule: a panel from before per-element answers replies to
// POST /events and /stats with a bare 200 and no body, which is success with
// nothing rejected — not a failed request to retry (the empty body used to
// surface as a decode netError, i.e. a retryable "panel failure").
func TestHTTPClient_EmptyBatchAnswerMeansAllAccepted(t *testing.T) {
	s := paneltest.NewStub(t)
	s.SetLegacyAnswers(true)
	c, log := newClient(t, s)

	ev := store.EventPayload{ID: "e0", Ts: 1757721540000, Kind: "panel", From: "PANEL_UP", To: "PANEL_DOWN"}
	evRes, err := c.PostEvents(context.Background(), []store.EventPayload{ev})
	if err != nil {
		t.Fatalf("PostEvents: %v, want an empty 200 read as success", err)
	}
	if len(evRes.Rejected) != 0 {
		t.Fatalf("events result = %+v, want nothing rejected", evRes)
	}

	st := panel.StatPayload{MonClientId: "ams-1", InboundKind: "xray", InboundId: 12, Path: "direct", BucketStart: 1757721300000}
	stRes, err := c.PostStats(context.Background(), []panel.StatPayload{st})
	if err != nil {
		t.Fatalf("PostStats: %v, want an empty 200 read as success", err)
	}
	if len(stRes.Rejected) != 0 {
		t.Fatalf("stats result = %+v, want nothing rejected", stRes)
	}
	wantDelays(t, log.delays())
}

// TestHTTPClient_EmptyStateBodyIsStillAnError keeps the empty-body allowance
// where it belongs: GET /state has no "nothing to say" answer, and an empty
// 200 there must not decode as a zero-value snapshot.
func TestHTTPClient_EmptyStateBodyIsStillAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Mon-Contract", "1")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	c := panel.NewHTTPClient(srv.URL, "t", clock.NewFake(testTime),
		panel.WithSleeper(func(context.Context, time.Duration) error { return nil }))
	if _, err := c.State(context.Background()); err == nil {
		t.Fatal("State on an empty 200 = nil error, want a failure")
	}
}

// TestHTTPClient_DecodesRejected checks the per-element answer shape of
// decision #50: {accepted, rejected:[{index, id?, error}]}.
func TestHTTPClient_DecodesRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Mon-Contract", "1")
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = w.Write([]byte(`{"accepted":1,"rejected":[{"index":1,"id":"e1","error":"from: unknown value \"NEVER\""}]}`))
	}))
	t.Cleanup(srv.Close)

	c := panel.NewHTTPClient(srv.URL, "t", clock.NewFake(testTime))
	res, err := c.PostEvents(context.Background(), make([]store.EventPayload, 2))
	if err != nil {
		t.Fatalf("PostEvents: %v", err)
	}
	if res.Accepted != 1 || len(res.Rejected) != 1 || res.Rejected[0] != (panel.Rejected{Index: 1, Id: "e1", Error: `from: unknown value "NEVER"`}) {
		t.Fatalf("result = %+v, want accepted 1 and index 1 rejected", res)
	}
}

// TestRejections_PlacesEntriesOnTheBatch checks how a rejected list maps
// back onto the batch that was sent: by index, by id when the two disagree
// (the id is the event's real identity), and not at all for an entry that
// names nothing in the batch — that element stays accepted.
func TestRejections_PlacesEntriesOnTheBatch(t *testing.T) {
	ids := []string{"a", "b", "c"}
	cases := []struct {
		name string
		ids  []string
		in   []panel.Rejected
		want []int
	}{
		{"by index", nil, []panel.Rejected{{Index: 2, Error: "x"}}, []int{2}},
		{"index and id agree", ids, []panel.Rejected{{Index: 1, Id: "b", Error: "x"}}, []int{1}},
		{"id wins over a wrong index", ids, []panel.Rejected{{Index: 0, Id: "c", Error: "x"}}, []int{2}},
		{"index out of range", nil, []panel.Rejected{{Index: 3, Error: "x"}, {Index: -1, Error: "x"}}, nil},
		{"unknown id", ids, []panel.Rejected{{Index: 1, Id: "zzz", Error: "x"}}, nil},
		{"nothing rejected", ids, nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := panel.Rejections(3, tc.in, tc.ids)
			if len(got) != len(tc.want) {
				t.Fatalf("Rejections = %v, want indices %v", got, tc.want)
			}
			for _, i := range tc.want {
				if _, ok := got[i]; !ok {
					t.Fatalf("Rejections = %v, want indices %v", got, tc.want)
				}
			}
		})
	}
}
