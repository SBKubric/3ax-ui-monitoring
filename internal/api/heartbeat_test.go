package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
	"github.com/SBKubric/3ax-ui-monitoring/internal/state"
)

// heartbeatTestTime is where the fake clock of these tests stands.
var heartbeatTestTime = time.Date(2025, 9, 13, 10, 0, 0, 0, time.UTC)

// heartbeatTestToken is the client token the stub authenticator accepts.
const (
	heartbeatTestToken  = "a-client-token"
	heartbeatTestClient = "ams-1"
)

// heartbeatStubAuth resolves exactly one token, the way internal/registry will.
type heartbeatStubAuth struct{}

// AuthenticateClient implements Authenticator.
func (heartbeatStubAuth) AuthenticateClient(_ context.Context, token string) (Identity, error) {
	if token != heartbeatTestToken {
		return Identity{}, ErrTokenRevoked
	}
	return Identity{MonClientID: heartbeatTestClient}, nil
}

// heartbeatStubService records what the handler passed to the state machine
// and answers with a canned acknowledgement.
type heartbeatStubService struct {
	mu    sync.Mutex
	calls int
	gotID string
	got   state.Heartbeat
	ack   state.HeartbeatAck
	err   error
}

// Heartbeat implements HeartbeatService.
func (s *heartbeatStubService) Heartbeat(_ context.Context, monClientID string, hb state.Heartbeat) (state.HeartbeatAck, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	s.gotID = monClientID
	s.got = hb
	return s.ack, s.err
}

// heartbeatTestServer mounts the route on a test server.
func heartbeatTestServer(t *testing.T, svc HeartbeatService) *httptest.Server {
	t.Helper()
	s := New(heartbeatStubAuth{}, clock.NewFake(heartbeatTestTime), slog.New(slog.DiscardHandler))
	RegisterHeartbeatRoutes(s, svc)
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	return srv
}

// heartbeatPost sends one request, with a bearer token when one is given.
func heartbeatPost(t *testing.T, srv *httptest.Server, token, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/v1/heartbeat", strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("post heartbeat: %v", err)
	}
	t.Cleanup(func() { _ = res.Body.Close() })
	return res
}

// heartbeatBody is the example body of mon-protocol.md §5.3.
const heartbeatBody = `{
  "monClientId": "ams-1", "configRevision": "3a91c0de77b1f2e4",
  "client": {"version": "0.1.0", "xrayVersion": "26.3.27", "uptimeMs": 86400000, "configError": null},
  "cycles": [
    {"seq": 1441, "ts": 1757721600000, "unverified": false, "results": [
      {"inboundKind": "xray", "inboundId": 12, "path": "proxy", "ok": true,
       "connectMs": 3, "tlsMs": 47, "ttfbMs": 39, "handshakeMs": null, "egressIp": "203.0.113.10", "reason": null, "detail": null},
      {"inboundKind": "awg", "inboundId": 0, "path": "proxy", "ok": false,
       "connectMs": null, "tlsMs": null, "ttfbMs": null, "handshakeMs": null, "egressIp": null,
       "reason": "awg_no_handshake", "detail": "last_handshake_time=0 after 20000ms"}
    ]}
  ]
}`

// TestHeartbeatRouteAnswersTheAcknowledgement walks the protocol §5.3 example
// through the handler.
func TestHeartbeatRouteAnswersTheAcknowledgement(t *testing.T) {
	svc := &heartbeatStubService{ack: state.HeartbeatAck{
		ConfigRevision: "3a91c0de77b1f2e4", ServerTS: clock.MS(heartbeatTestTime), AckSeq: 1441,
	}}
	srv := heartbeatTestServer(t, svc)

	res := heartbeatPost(t, srv, heartbeatTestToken, heartbeatBody)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}
	if got := res.Header.Get("Content-Type"); got != "application/json; charset=utf-8" {
		t.Errorf("content type = %q", got)
	}
	var ack state.HeartbeatAck
	if err := json.NewDecoder(res.Body).Decode(&ack); err != nil {
		t.Fatalf("decode answer: %v", err)
	}
	if ack != svc.ack {
		t.Errorf("answer = %+v, want %+v", ack, svc.ack)
	}

	if svc.gotID != heartbeatTestClient {
		t.Errorf("service got mon-client %q, want the authenticated %q", svc.gotID, heartbeatTestClient)
	}
	if len(svc.got.Cycles) != 1 {
		t.Fatalf("service got %d cycles, want one", len(svc.got.Cycles))
	}
	cycle := svc.got.Cycles[0]
	if cycle.Seq != 1441 || cycle.TS != 1757721600000 || cycle.Unverified {
		t.Errorf("cycle = %+v, want seq 1441 at 1757721600000, verified", cycle)
	}
	if len(cycle.Results) != 2 {
		t.Fatalf("cycle carries %d results, want two", len(cycle.Results))
	}
	if !cycle.Results[0].OK || cycle.Results[0].TLSMS == nil || *cycle.Results[0].TLSMS != 47 {
		t.Errorf("first result = %+v, want the successful xray probe with tlsMs 47", cycle.Results[0])
	}
	if cycle.Results[1].OK || cycle.Results[1].Reason != "awg_no_handshake" {
		t.Errorf("second result = %+v, want the failed awg probe", cycle.Results[1])
	}
	if svc.got.Client.Version != "0.1.0" || svc.got.Client.ConfigError != "" {
		t.Errorf("client report = %+v, want version 0.1.0 and no config error", svc.got.Client)
	}
}

// TestHeartbeatRouteRejections covers the two failures the protocol pins: an
// unauthenticated heartbeat and one whose body cannot be read.
func TestHeartbeatRouteRejections(t *testing.T) {
	cases := []struct {
		name     string
		token    string
		body     string
		want     int
		wantCode string
		wantCall bool
	}{
		{name: "without a token", body: heartbeatBody, want: http.StatusUnauthorized, wantCode: ErrCodeTokenRevoked},
		{name: "with a revoked token", token: "someone-elses-token", body: heartbeatBody, want: http.StatusUnauthorized, wantCode: ErrCodeTokenRevoked},
		{name: "with a malformed body", token: heartbeatTestToken, body: `{"cycles": [`, want: http.StatusBadRequest, wantCode: ErrCodeInvalidBody},
		{name: "with an empty body", token: heartbeatTestToken, body: "", want: http.StatusBadRequest, wantCode: ErrCodeInvalidBody},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := &heartbeatStubService{}
			srv := heartbeatTestServer(t, svc)
			res := heartbeatPost(t, srv, tc.token, tc.body)
			if res.StatusCode != tc.want {
				t.Fatalf("status = %d, want %d", res.StatusCode, tc.want)
			}
			var body ErrorBody
			if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
				t.Fatalf("decode error body: %v", err)
			}
			if body.Error != tc.wantCode {
				t.Errorf("error code = %q, want %q", body.Error, tc.wantCode)
			}
			if svc.calls != 0 {
				t.Errorf("the state machine was called %d times for a rejected request", svc.calls)
			}
		})
	}
}

// TestHeartbeatRouteReportsAFailedApply checks that a state machine failure is
// an internal error, not a silent 200: the mon-client must keep its cycles and
// resend them.
func TestHeartbeatRouteReportsAFailedApply(t *testing.T) {
	svc := &heartbeatStubService{err: context.DeadlineExceeded}
	srv := heartbeatTestServer(t, svc)
	res := heartbeatPost(t, srv, heartbeatTestToken, heartbeatBody)
	if res.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", res.StatusCode)
	}
	var body ErrorBody
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	if body.Error != ErrCodeInternal {
		t.Errorf("error code = %q, want %q", body.Error, ErrCodeInternal)
	}
}
