package panel_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
	"github.com/SBKubric/3ax-ui-monitoring/internal/panel"
	"github.com/SBKubric/3ax-ui-monitoring/internal/paneltest"
)

// delayLog records the backoff waits the client asked for without performing
// them, so that the 1 s → 2 s → 4 s sequence can be asserted in microseconds.
type delayLog struct {
	mu     sync.Mutex
	delays []time.Duration
	onWait func(d time.Duration)
}

func (d *delayLog) backoff(ctx context.Context, attempt int) error {
	delay := panel.BackoffDelay(attempt)
	d.mu.Lock()
	d.delays = append(d.delays, delay)
	onWait := d.onWait
	d.mu.Unlock()
	if onWait != nil {
		onWait(delay)
	}
	return ctx.Err()
}

func (d *delayLog) all() []time.Duration {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]time.Duration, len(d.delays))
	copy(out, d.delays)
	return out
}

// syncBuffer collects log output from whichever goroutine the client runs on.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type harness struct {
	stub   *paneltest.Stub
	client *panel.Client
	delays *delayLog
	logs   *syncBuffer
}

func newHarness(t *testing.T, mutate ...func(*panel.Options)) *harness {
	t.Helper()
	h := &harness{
		stub:   paneltest.NewStub(t),
		delays: &delayLog{},
		logs:   &syncBuffer{},
	}
	opts := panel.Options{
		BaseURL: h.stub.URL(),
		Token:   paneltest.DefaultToken,
		Clock:   clock.System{},
		Log:     slog.New(slog.NewTextHandler(h.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Timeout: 2 * time.Second,
		Backoff: h.delays.backoff,
	}
	for _, m := range mutate {
		m(&opts)
	}
	client, err := panel.New(opts)
	if err != nil {
		t.Fatalf("panel.New: %v", err)
	}
	h.client = client
	return h
}

func equalDelays(got []time.Duration, want ...time.Duration) bool {
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

func TestNewValidatesOptions(t *testing.T) {
	cases := []struct {
		name    string
		opts    panel.Options
		wantErr bool
	}{
		{name: "ok", opts: panel.Options{BaseURL: "https://panel.example.net:2053/xyz/", Token: "t"}},
		{name: "empty base url", opts: panel.Options{Token: "t"}, wantErr: true},
		{name: "empty token", opts: panel.Options{BaseURL: "https://panel.example.net/"}, wantErr: true},
		{name: "not http", opts: panel.Options{BaseURL: "ftp://panel.example.net/", Token: "t"}, wantErr: true},
		{name: "no host", opts: panel.Options{BaseURL: "https:///mon", Token: "t"}, wantErr: true},
		{name: "unparseable", opts: panel.Options{BaseURL: "https://exa mple.net/\x7f", Token: "t"}, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, err := panel.New(tc.opts)
			if tc.wantErr {
				if !errors.Is(err, panel.ErrInvalidOptions) {
					t.Fatalf("err = %v, want ErrInvalidOptions", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if got, want := client.BaseURL(), "https://panel.example.net:2053/xyz/mon/v1"; got != want {
				t.Fatalf("BaseURL() = %q, want %q", got, want)
			}
		})
	}
}

func TestClientJoinsBasePath(t *testing.T) {
	cases := []struct {
		name   string
		suffix string
		want   string
	}{
		{name: "no web base path", suffix: "", want: "/mon/v1/state"},
		{name: "trailing slash", suffix: "/", want: "/mon/v1/state"},
		{name: "web base path", suffix: "/xyz", want: "/xyz/mon/v1/state"},
		{name: "web base path with trailing slash", suffix: "/xyz/", want: "/xyz/mon/v1/state"},
		{name: "nested web base path", suffix: "/a/b/", want: "/a/b/mon/v1/state"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, func(o *panel.Options) { o.BaseURL += tc.suffix })
			if _, err := h.client.State(t.Context()); err != nil {
				t.Fatalf("State: %v", err)
			}
			requests := h.stub.Requests()
			if len(requests) != 1 {
				t.Fatalf("got %d requests, want 1", len(requests))
			}
			if got := requests[0].Path; got != tc.want {
				t.Fatalf("path = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestClientSendsBearerAndContentType(t *testing.T) {
	h := newHarness(t)
	if _, err := h.client.State(t.Context()); err != nil {
		t.Fatalf("State: %v", err)
	}
	if _, err := h.client.SendEvents(t.Context(), []panel.Event{panelEvent()}); err != nil {
		t.Fatalf("SendEvents: %v", err)
	}
	requests := h.stub.Requests()
	if len(requests) != 2 {
		t.Fatalf("got %d requests, want 2", len(requests))
	}
	for _, r := range requests {
		if got, want := r.Header.Get("Authorization"), "Bearer "+paneltest.DefaultToken; got != want {
			t.Errorf("%s %s: Authorization = %q, want %q", r.Method, r.Endpoint, got, want)
		}
	}
	if got := requests[0].Header.Get("Content-Type"); got != "" {
		t.Errorf("GET /state: Content-Type = %q, want none", got)
	}
	if got, want := requests[1].Header.Get("Content-Type"), panel.ContentTypeJSON; got != want {
		t.Errorf("POST /events: Content-Type = %q, want %q", got, want)
	}
}

func TestClientStateHappyPath(t *testing.T) {
	h := newHarness(t)
	h.stub.SetOverride(true, "front.example.net")

	state, err := h.client.State(t.Context())
	if err != nil {
		t.Fatalf("State: %v", err)
	}
	if state.Contract != panel.Contract {
		t.Errorf("contract = %d, want %d", state.Contract, panel.Contract)
	}
	if state.Revision != paneltest.DefaultRevision {
		t.Errorf("revision = %q, want %q", state.Revision, paneltest.DefaultRevision)
	}
	if !state.Override.Enabled || state.Override.Host != "front.example.net" {
		t.Errorf("override = %+v, want enabled front.example.net", state.Override)
	}
	if state.Probe.Ensured() {
		t.Errorf("probe.subId = %q, want null before the first ensure", state.Probe.SubIDValue())
	}
	if len(state.Inbounds) != 2 {
		t.Fatalf("got %d inbounds, want 2", len(state.Inbounds))
	}
	if state.Inbounds[1].Kind != panel.InboundKindAWG || state.Inbounds[1].InboundID != 0 {
		t.Errorf("awg inbound = %+v, want kind awg id 0", state.Inbounds[1])
	}
	if state.Stale.ThresholdMinutes != 15 {
		t.Errorf("stale.thresholdMinutes = %d, want 15", state.Stale.ThresholdMinutes)
	}

	h.stub.SetProbeSubID("k3j9d8s7f6g5h4j3")
	state, err = h.client.State(t.Context())
	if err != nil {
		t.Fatalf("State: %v", err)
	}
	if !state.Probe.Ensured() || state.Probe.SubIDValue() != "k3j9d8s7f6g5h4j3" {
		t.Errorf("probe = %+v, want the ensured subId", state.Probe)
	}
}

func TestClientBareNotFoundIsNotRetried(t *testing.T) {
	cases := []struct {
		name  string
		setup func(*paneltest.Stub)
	}{
		{name: "wrong token", setup: func(s *paneltest.Stub) { s.SetToken("not-the-token") }},
		{name: "monitoring disabled", setup: func(s *paneltest.Stub) { s.Fail(paneltest.Any, paneltest.NotFound()) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			tc.setup(h.stub)

			_, err := h.client.State(t.Context())
			if !errors.Is(err, panel.ErrNotFound) {
				t.Fatalf("err = %v, want ErrNotFound", err)
			}
			if errors.Is(err, panel.ErrUnavailable) {
				t.Errorf("err = %v, must not count towards PANEL_DOWN", err)
			}
			if !errors.Is(err, panel.ErrRejected) {
				t.Errorf("err = %v, want it dropped like any other 4xx", err)
			}
			if n := h.stub.Count(paneltest.Any); n != 1 {
				t.Errorf("made %d requests, want exactly 1: a 404 is never retried", n)
			}
			if d := h.delays.all(); len(d) != 0 {
				t.Errorf("waited %v, want no backoff", d)
			}
			var apiErr *panel.APIError
			if !errors.As(err, &apiErr) || apiErr.Status != http.StatusNotFound {
				t.Fatalf("err = %v, want an APIError with status 404", err)
			}
			if apiErr.Code != "" || apiErr.Message != "" {
				t.Errorf("apiErr = %+v, want no body on a bare 404", apiErr)
			}
		})
	}
}

func TestClientRetriesTransportFailures(t *testing.T) {
	cases := []struct {
		name         string
		timeout      time.Duration
		setup        func(*testing.T, *harness)
		wantReason   string
		wantRequests int
	}{
		{
			name:         "5xx",
			setup:        func(_ *testing.T, h *harness) { h.stub.Fail(paneltest.State, paneltest.ServerError()) },
			wantReason:   panel.ReasonHTTP5xx,
			wantRequests: 4,
		},
		{
			name:         "503 while the panel starts",
			setup:        func(_ *testing.T, h *harness) { h.stub.Fail(paneltest.State, paneltest.Starting()) },
			wantReason:   panel.ReasonHTTP5xx,
			wantRequests: 4,
		},
		{
			name:         "timeout",
			timeout:      80 * time.Millisecond,
			setup:        func(_ *testing.T, h *harness) { h.stub.Fail(paneltest.State, paneltest.Hanging()) },
			wantReason:   panel.ReasonHTTPTimeout,
			wantRequests: 4,
		},
		{
			name:         "connection refused",
			setup:        func(_ *testing.T, h *harness) { h.stub.Close() },
			wantReason:   panel.ReasonConnRefused,
			wantRequests: 0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, func(o *panel.Options) {
				if tc.timeout > 0 {
					// No timeout on the http.Client: the per-request
					// context is what must end a hung request.
					o.Timeout = tc.timeout
					o.HTTPClient = &http.Client{}
				}
			})
			tc.setup(t, h)

			_, err := h.client.State(t.Context())
			if !errors.Is(err, panel.ErrUnavailable) {
				t.Fatalf("err = %v, want ErrUnavailable", err)
			}
			if got := panel.FailureReason(err); got != tc.wantReason {
				t.Errorf("FailureReason = %q, want %q", got, tc.wantReason)
			}
			if got := h.delays.all(); !equalDelays(got, time.Second, 2*time.Second, 4*time.Second) {
				t.Errorf("backoff = %v, want [1s 2s 4s]", got)
			}
			if tc.wantRequests > 0 {
				if n := h.stub.Count(paneltest.Any); n != tc.wantRequests {
					t.Errorf("made %d requests, want %d", n, tc.wantRequests)
				}
			}
			var te *panel.TransportError
			if !errors.As(err, &te) {
				t.Fatalf("err = %v, want a *TransportError", err)
			}
			if te.Attempts != 4 {
				t.Errorf("attempts = %d, want 4", te.Attempts)
			}
		})
	}
}

func TestClientSucceedsAfterRetry(t *testing.T) {
	h := newHarness(t)
	h.stub.Fail(paneltest.State, paneltest.ServerError().NTimes(2))

	if _, err := h.client.State(t.Context()); err != nil {
		t.Fatalf("State: %v", err)
	}
	if got := h.delays.all(); !equalDelays(got, time.Second, 2*time.Second) {
		t.Errorf("backoff = %v, want [1s 2s]", got)
	}
	if n := h.stub.Count(paneltest.State); n != 3 {
		t.Errorf("made %d requests, want 3", n)
	}
}

func TestClientDropsFourXXWithoutRetry(t *testing.T) {
	h := newHarness(t)
	h.stub.Fail(paneltest.Events, paneltest.InvalidBody(`events[3].kind: unknown value "foo"`))

	_, err := h.client.SendEvents(t.Context(), []panel.Event{targetEvent("ams-1")})
	if !errors.Is(err, panel.ErrRejected) {
		t.Fatalf("err = %v, want ErrRejected", err)
	}
	if errors.Is(err, panel.ErrUnavailable) {
		t.Errorf("err = %v, a rejected batch must not count towards PANEL_DOWN", err)
	}
	if n := h.stub.Count(paneltest.Events); n != 1 {
		t.Errorf("made %d requests, want 1: a 4xx is logged and dropped", n)
	}
	if d := h.delays.all(); len(d) != 0 {
		t.Errorf("waited %v, want no backoff", d)
	}
	var apiErr *panel.APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("err = %v, want an APIError", err)
	}
	if apiErr.Status != http.StatusBadRequest || apiErr.Code != panel.CodeInvalidBody {
		t.Errorf("apiErr = %+v, want 400 invalid_body", apiErr)
	}
	if !strings.Contains(apiErr.Message, "unknown value") {
		t.Errorf("message = %q, want the panel's message", apiErr.Message)
	}
	if !strings.Contains(h.logs.String(), "not retrying") {
		t.Errorf("logs = %q, want the drop logged", h.logs.String())
	}
}

func TestClientSentinelsPerEndpoint(t *testing.T) {
	cases := []struct {
		name    string
		failure paneltest.Failure
		call    func(*harness) error
		want    error
	}{
		{
			name:    "override disabled",
			failure: paneltest.OverrideDisabled(),
			call:    func(h *harness) error { _, err := h.client.ProbeConfigs(t.Context(), ""); return err },
			want:    panel.ErrOverrideDisabled,
		},
		{
			name:    "probe not ensured",
			failure: paneltest.ProbeNotEnsured(),
			call:    func(h *harness) error { _, err := h.client.ProbeConfigs(t.Context(), "real.example.net"); return err },
			want:    panel.ErrProbeNotEnsured,
		},
		{
			name:    "batch too large",
			failure: paneltest.BatchTooLarge(),
			call: func(h *harness) error {
				_, err := h.client.SendStats(t.Context(), []panel.Stat{emptyStat()})
				return err
			},
			want: panel.ErrBatchTooLarge,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			h.stub.Fail(paneltest.Any, tc.failure)

			err := tc.call(h)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if errors.Is(err, panel.ErrUnavailable) {
				t.Errorf("err = %v, the panel answered, so it is not an outage", err)
			}
			if n := h.stub.Count(paneltest.Any); n != 1 {
				t.Errorf("made %d requests, want 1", n)
			}
		})
	}
}

func TestClientXrayUnavailableIsNotRetried(t *testing.T) {
	h := newHarness(t)
	h.stub.Fail(paneltest.ProbeEnsure, paneltest.XrayUnavailable())

	_, err := h.client.ProbeEnsure(t.Context(), nil)
	if !errors.Is(err, panel.ErrXrayUnavailable) {
		t.Fatalf("err = %v, want ErrXrayUnavailable", err)
	}
	if errors.Is(err, panel.ErrUnavailable) {
		t.Errorf("err = %v: the panel answered, the next cycle finishes the probe set", err)
	}
	if n := h.stub.Count(paneltest.ProbeEnsure); n != 1 {
		t.Errorf("made %d requests, want 1", n)
	}
	if d := h.delays.all(); len(d) != 0 {
		t.Errorf("waited %v, want no backoff", d)
	}
}

func TestClientRetryBudgetStaysInsideTheCycle(t *testing.T) {
	fake := clock.NewFake(time.Now())
	h := newHarness(t, func(o *panel.Options) { o.Clock = fake })
	// Waiting out a backoff moves the client's clock, not the wall clock, so
	// the budget is spent without the test spending any time.
	h.delays.onWait = fake.Advance
	h.stub.Fail(paneltest.State, paneltest.ServerError())

	ctx, cancel := context.WithDeadline(t.Context(), fake.Now().Add(2500*time.Millisecond))
	defer cancel()

	_, err := h.client.State(ctx)
	if !errors.Is(err, panel.ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", err)
	}
	// One second of backoff fits in the budget; the two seconds before the
	// third attempt do not, so the client gives up rather than overrun.
	if got := h.delays.all(); !equalDelays(got, time.Second) {
		t.Errorf("backoff = %v, want [1s]", got)
	}
	if n := h.stub.Count(paneltest.State); n != 2 {
		t.Errorf("made %d requests, want 2", n)
	}
	if !strings.Contains(h.logs.String(), "retry budget spent") {
		t.Errorf("logs = %q, want the abandoned retry logged", h.logs.String())
	}
}

func TestClientRequestTimeoutIsHonoured(t *testing.T) {
	if panel.DefaultTimeout != 10*time.Second {
		t.Fatalf("DefaultTimeout = %v, want 10s", panel.DefaultTimeout)
	}
	h := newHarness(t, func(o *panel.Options) {
		o.Timeout = 60 * time.Millisecond
		o.HTTPClient = &http.Client{}
	})
	h.stub.Fail(paneltest.State, paneltest.Hanging().Once())

	// The first attempt never gets an answer; the per-request timeout ends it
	// and the retry succeeds, so a hung panel costs one timeout, not the cycle.
	if _, err := h.client.State(t.Context()); err != nil {
		t.Fatalf("State: %v", err)
	}
	if n := h.stub.Count(paneltest.State); n != 2 {
		t.Errorf("made %d requests, want 2", n)
	}
}

func TestClientHonoursCallerCancellation(t *testing.T) {
	h := newHarness(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	_, err := h.client.State(ctx)
	if err == nil {
		t.Fatal("State: want an error on a cancelled context")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if errors.Is(err, panel.ErrUnavailable) {
		t.Errorf("err = %v: mon-server gave up, the panel did not fail", err)
	}
	if d := h.delays.all(); len(d) != 0 {
		t.Errorf("waited %v, want no backoff on a cancelled context", d)
	}
}

func TestClientHonoursCancellationDuringBackoff(t *testing.T) {
	h := newHarness(t)
	h.stub.Fail(paneltest.State, paneltest.ServerError())
	ctx, cancel := context.WithCancel(t.Context())
	h.delays.onWait = func(time.Duration) { cancel() }

	_, err := h.client.State(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if errors.Is(err, panel.ErrUnavailable) {
		t.Errorf("err = %v: mon-server stopped waiting, the panel is not the reason", err)
	}
	if n := h.stub.Count(paneltest.State); n != 1 {
		t.Errorf("made %d requests, want 1", n)
	}
}

func TestClientProbeEnsure(t *testing.T) {
	h := newHarness(t)
	snapshot := []panel.MonClientSnapshot{
		{ID: "ams-1", Name: "Amsterdam #1", Region: "NL", State: panel.MonClientOnline, LastHeartbeat: 1757721590000},
		{ID: "msk-1", Name: "Moscow #1", Region: "RU", State: panel.MonClientOffline, LastHeartbeat: 1757720000000},
	}

	result, err := h.client.ProbeEnsure(t.Context(), snapshot)
	if err != nil {
		t.Fatalf("ProbeEnsure: %v", err)
	}
	if result.SubID == "" {
		t.Error("subId is empty, want the probe set's subscription id")
	}
	if result.Revision != paneltest.DefaultRevision {
		t.Errorf("revision = %q, want %q", result.Revision, paneltest.DefaultRevision)
	}
	if len(result.Created) != 2 || result.Present != 2 {
		t.Errorf("created = %+v, present = %d, want both inbounds", result.Created, result.Present)
	}

	got := h.stub.EnsureSnapshots()
	if len(got) != 1 {
		t.Fatalf("got %d snapshots, want 1", len(got))
	}
	if len(got[0]) != 2 || got[0][0].ID != "ams-1" || got[0][1].State != panel.MonClientOffline {
		t.Errorf("snapshot = %+v, want the registry as posted", got[0])
	}
}

func TestClientProbeEnsureSendsEmptySnapshotAsList(t *testing.T) {
	h := newHarness(t)
	if _, err := h.client.ProbeEnsure(t.Context(), nil); err != nil {
		t.Fatalf("ProbeEnsure: %v", err)
	}
	body := string(bytes.TrimSpace(h.stub.Requests()[0].Body))
	if body != `{"monClients":[]}` {
		t.Errorf("body = %s, want an empty list, never null", body)
	}
}

func TestClientProbeConfigsPerPath(t *testing.T) {
	cases := []struct {
		name      string
		host      string
		override  bool
		wantPath  string
		wantQuery string
		wantErr   error
	}{
		{name: "direct", host: "real.example.net", wantPath: panel.PathDirect, wantQuery: "host=real.example.net"},
		{name: "proxy", override: true, wantPath: panel.PathProxy},
		{name: "proxy without override", wantErr: panel.ErrOverrideDisabled},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			h.stub.SetProbeSubID("k3j9d8s7f6g5h4j3")
			if tc.override {
				h.stub.SetOverride(true, "front.example.net")
			}

			configs, err := h.client.ProbeConfigs(t.Context(), tc.host)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ProbeConfigs: %v", err)
			}
			if configs.Path != tc.wantPath {
				t.Errorf("path = %q, want %q", configs.Path, tc.wantPath)
			}
			if configs.Revision != paneltest.DefaultRevision {
				t.Errorf("revision = %q, want %q", configs.Revision, paneltest.DefaultRevision)
			}
			if len(configs.Items) != 2 {
				t.Fatalf("got %d items, want 2", len(configs.Items))
			}
			if configs.Items[0].Link == "" {
				t.Error("xray item has no link")
			}
			if configs.Items[1].Conf == "" || configs.Items[1].Filename == "" {
				t.Errorf("awg item = %+v, want a named conf", configs.Items[1])
			}
			if got := h.stub.Requests()[0].Query.Encode(); got != tc.wantQuery {
				t.Errorf("query = %q, want %q", got, tc.wantQuery)
			}
		})
	}
}

func TestClientProbeConfigsBeforeEnsure(t *testing.T) {
	h := newHarness(t)
	if _, err := h.client.ProbeConfigs(t.Context(), "real.example.net"); !errors.Is(err, panel.ErrProbeNotEnsured) {
		t.Fatalf("err = %v, want ErrProbeNotEnsured", err)
	}
}

func TestClientDeleteProbe(t *testing.T) {
	h := newHarness(t)
	h.stub.SetProbeSubID("k3j9d8s7f6g5h4j3")

	if err := h.client.DeleteProbe(t.Context()); err != nil {
		t.Fatalf("DeleteProbe: %v", err)
	}
	if !h.stub.ProbeDeleted() {
		t.Error("the probe set is still there")
	}
	if state := h.stub.State(); state.Probe.Ensured() {
		t.Errorf("probe = %+v, want the subId forgotten", state.Probe)
	}
}

func TestClientSendEvents(t *testing.T) {
	h := newHarness(t)
	events := []panel.Event{targetEvent("ams-1"), monClientEvent("msk-1"), panelEvent()}

	result, err := h.client.SendEvents(t.Context(), events)
	if err != nil {
		t.Fatalf("SendEvents: %v", err)
	}
	if result.Accepted != 3 || result.Duplicates != 0 || len(result.Ignored) != 0 {
		t.Errorf("result = %+v, want three accepted", result)
	}
	if got := h.stub.Events(); len(got) != 3 || got[0].MonClientID != "ams-1" {
		t.Errorf("recorded = %+v, want the batch as posted", got)
	}

	// Resending the same ids is safe: the panel counts them as duplicates.
	result, err = h.client.SendEvents(t.Context(), events)
	if err != nil {
		t.Fatalf("SendEvents again: %v", err)
	}
	if result.Duplicates != 3 || result.Accepted != 0 {
		t.Errorf("result = %+v, want three duplicates", result)
	}
}

func TestClientSendEventsWireShape(t *testing.T) {
	h := newHarness(t)
	// A panel event built sloppily, with target fields left over: they must not
	// reach the wire.
	sloppy := panelEvent()
	sloppy.MonClientID = "ams-1"
	sloppy.InboundKind = panel.InboundKindXray
	sloppy.InboundID = panel.Int64Ptr(12)
	sloppy.Path = panel.PathProxy
	sloppy.Notified = false

	if _, err := h.client.SendEvents(t.Context(), []panel.Event{sloppy, awgTargetEvent()}); err != nil {
		t.Fatalf("SendEvents: %v", err)
	}

	raw := h.stub.RawEvents()
	if len(raw) != 2 {
		t.Fatalf("got %d events, want 2", len(raw))
	}
	got := decodeMap(t, raw[0])
	for _, absent := range []string{"monClientId", "inboundKind", "inboundId", "path"} {
		if _, ok := got[absent]; ok {
			t.Errorf("panel event carries %q, want it omitted", absent)
		}
	}
	if got["notified"] != true {
		t.Errorf("notified = %v, want true: mon-server already sent it itself", got["notified"])
	}

	awg := decodeMap(t, raw[1])
	if v, ok := awg["inboundId"]; !ok || v.(float64) != 0 {
		t.Errorf("awg inboundId = %v, want 0 on the wire, never omitted", awg["inboundId"])
	}
}

func TestClientEnforcesBatchLimits(t *testing.T) {
	cases := []struct {
		name string
		call func(*harness) error
	}{
		{
			name: "events over the limit",
			call: func(h *harness) error {
				events := make([]panel.Event, panel.MaxEvents+1)
				for i := range events {
					events[i] = targetEvent(fmt.Sprintf("mc-%d", i))
				}
				_, err := h.client.SendEvents(t.Context(), events)
				return err
			},
		},
		{
			name: "stats over the limit",
			call: func(h *harness) error {
				stats := make([]panel.Stat, panel.MaxStats+1)
				for i := range stats {
					stats[i] = emptyStat()
				}
				_, err := h.client.SendStats(t.Context(), stats)
				return err
			},
		},
		{
			name: "mon-clients over the limit",
			call: func(h *harness) error {
				snapshot := make([]panel.MonClientSnapshot, panel.MaxMonClients+1)
				_, err := h.client.ProbeEnsure(t.Context(), snapshot)
				return err
			},
		},
		{
			name: "body over one mebibyte",
			call: func(h *harness) error {
				event := targetEvent("ams-1")
				event.Reason = strings.Repeat("x", panel.MaxBodyBytes)
				_, err := h.client.SendEvents(t.Context(), []panel.Event{event})
				return err
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			err := tc.call(h)
			if !errors.Is(err, panel.ErrBatchTooLarge) {
				t.Fatalf("err = %v, want ErrBatchTooLarge", err)
			}
			if n := h.stub.Count(paneltest.Any); n != 0 {
				t.Errorf("made %d requests, want none: the limit is enforced before sending", n)
			}
		})
	}
}

func TestClientEmptyBatchesMakeNoRequest(t *testing.T) {
	h := newHarness(t)
	if _, err := h.client.SendEvents(t.Context(), nil); err != nil {
		t.Fatalf("SendEvents: %v", err)
	}
	if _, err := h.client.SendStats(t.Context(), nil); err != nil {
		t.Fatalf("SendStats: %v", err)
	}
	if n := h.stub.Count(paneltest.Any); n != 0 {
		t.Errorf("made %d requests, want none", n)
	}
}

func TestClientSendStatsNullableLatency(t *testing.T) {
	h := newHarness(t)
	stats := []panel.Stat{
		{
			MonClientID: "ams-1", InboundKind: panel.InboundKindXray, InboundID: 12,
			Path: panel.PathProxy, BucketStart: 1757721300000, NOk: 5, NFail: 0,
			LatencyMinMS: panel.Int64Ptr(41),
			LatencyAvgMS: panel.Int64Ptr(47),
			LatencyMaxMS: panel.Int64Ptr(58),
		},
		{
			MonClientID: "ams-1", InboundKind: panel.InboundKindAWG, InboundID: 0,
			Path: panel.PathDirect, BucketStart: 1757721300000, NOk: 0, NFail: 5,
		},
	}

	result, err := h.client.SendStats(t.Context(), stats)
	if err != nil {
		t.Fatalf("SendStats: %v", err)
	}
	if result.Accepted != 2 {
		t.Errorf("accepted = %d, want 2", result.Accepted)
	}

	raw := h.stub.RawStats()
	if len(raw) != 2 {
		t.Fatalf("got %d stats, want 2", len(raw))
	}
	ok := decodeMap(t, raw[0])
	if ok["latencyMinMs"] != float64(41) {
		t.Errorf("latencyMinMs = %v, want 41", ok["latencyMinMs"])
	}
	if v, present := ok["handshakeMs"]; !present || v != nil {
		t.Errorf("handshakeMs = %v (present %v), want null: it is AWG only", v, present)
	}
	failed := decodeMap(t, raw[1])
	for _, field := range []string{"latencyMinMs", "latencyAvgMs", "latencyMaxMs", "handshakeMs"} {
		v, present := failed[field]
		if !present {
			t.Errorf("%s is missing, want it present as null", field)
			continue
		}
		if v != nil {
			t.Errorf("%s = %v, want null with no successes, never 0", field, v)
		}
	}
}

func TestClientIgnoresUnknownResponseFields(t *testing.T) {
	h := newHarness(t)
	h.stub.Fail(paneltest.State, paneltest.Failure{
		Status: http.StatusOK,
		Body: `{"contract":1,"panelVersion":"1.9.0","serverTime":1757721600000,
			"revision":"abc","override":{"enabled":false,"host":"","mode":"nginx"},
			"probe":{"subId":null,"lastEnsured":0,"ttlHours":24},
			"inbounds":[{"kind":"xray","inboundId":12,"tag":"t","remark":"r","protocol":"vless",
				"port":443,"enable":true,"sniffing":{"enabled":true}}],
			"stale":{"thresholdMinutes":15},"futureSection":{"anything":[1,2,3]}}`,
	})

	state, err := h.client.State(t.Context())
	if err != nil {
		t.Fatalf("State: %v, want unknown fields ignored", err)
	}
	if state.Revision != "abc" || len(state.Inbounds) != 1 || state.Inbounds[0].Port != 443 {
		t.Errorf("state = %+v, want the known fields decoded", state)
	}
}

func TestClientRecordsContractHeader(t *testing.T) {
	cases := []struct {
		name        string
		header      string
		wantOK      bool
		wantPresent bool
		wantWarn    bool
	}{
		{name: "matching", header: "1", wantOK: true, wantPresent: true},
		{name: "newer contract", header: "2", wantPresent: true, wantWarn: true},
		{name: "absent", header: "", wantWarn: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			h.stub.SetContractHeader(tc.header)

			if _, err := h.client.State(t.Context()); err != nil {
				t.Fatalf("State: %v, a header mismatch must not fail the request", err)
			}
			got := h.client.LastContract()
			if got.OK != tc.wantOK || got.Present != tc.wantPresent || got.Value != tc.header {
				t.Errorf("LastContract() = %+v, want value %q present %v ok %v",
					got, tc.header, tc.wantPresent, tc.wantOK)
			}
			if warned := strings.Contains(h.logs.String(), "contract header mismatch"); warned != tc.wantWarn {
				t.Errorf("warned = %v, want %v", warned, tc.wantWarn)
			}
		})
	}
}

func TestClientIsSafeForConcurrentUse(t *testing.T) {
	h := newHarness(t)
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, err := h.client.State(t.Context()); err != nil {
				t.Errorf("State: %v", err)
			}
			if _, err := h.client.SendEvents(t.Context(), []panel.Event{monClientEvent(fmt.Sprintf("mc-%d", i))}); err != nil {
				t.Errorf("SendEvents: %v", err)
			}
			_ = h.client.LastContract()
		}(i)
	}
	wg.Wait()
	if n := h.stub.Count(paneltest.Any); n != 16 {
		t.Errorf("made %d requests, want 16", n)
	}
}

// --- fixtures ---

var eventSeq atomic.Int64

func nextEventID() string {
	return fmt.Sprintf("019254a0-7c3e-7d2a-9b4f-%012d", eventSeq.Add(1))
}

func targetEvent(monClientID string) panel.Event {
	return panel.Event{
		ID: nextEventID(), TS: 1757721540000, Kind: panel.EventKindTarget,
		MonClientID: monClientID, InboundKind: panel.InboundKindXray,
		InboundID: panel.Int64Ptr(12), Path: panel.PathProxy,
		From: panel.TargetUp, To: panel.TargetDown, Reason: panel.ReasonTLSTimeout,
	}
}

func awgTargetEvent() panel.Event {
	return panel.Event{
		ID: nextEventID(), TS: 1757721541000, Kind: panel.EventKindTarget,
		MonClientID: "ams-1", InboundKind: panel.InboundKindAWG,
		InboundID: panel.Int64Ptr(0), Path: panel.PathDirect,
		From: panel.TargetUp, To: panel.TargetDown, Reason: panel.ReasonAWGNoHandshake,
	}
}

func monClientEvent(monClientID string) panel.Event {
	return panel.Event{
		ID: nextEventID(), TS: 1757721545000, Kind: panel.EventKindMonClient,
		MonClientID: monClientID,
		From:        panel.MonClientOnline, To: panel.MonClientOffline,
		Reason: panel.ReasonHeartbeatMissed,
	}
}

func panelEvent() panel.Event {
	return panel.Event{
		ID: nextEventID(), TS: 1757721000000, Kind: panel.EventKindPanel,
		From: panel.PanelUp, To: panel.PanelDown, Reason: panel.ReasonHTTPTimeout,
		Notified: true,
	}
}

func emptyStat() panel.Stat {
	return panel.Stat{
		MonClientID: "ams-1", InboundKind: panel.InboundKindXray, InboundID: 12,
		Path: panel.PathProxy, BucketStart: 1757721300000, NFail: 5,
	}
}

func decodeMap(t *testing.T, raw json.RawMessage) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode %s: %v", raw, err)
	}
	return out
}
