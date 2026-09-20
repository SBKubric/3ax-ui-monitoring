package servertest

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/client/api"
	"github.com/SBKubric/3ax-ui-monitoring/internal/client/proto"
)

func decodeJSON(resp *http.Response, out any) error {
	return json.NewDecoder(resp.Body).Decode(out)
}

func newClient(t *testing.T, s *Stub) *api.Client {
	t.Helper()
	return api.New(s.URL(), s.HTTPClient())
}

// TestRegisterAndApprove drives the full happy path of protocol §2:
// register, poll pending, approve, poll approved (token once), poll again
// (token gone).
func TestRegisterAndApprove(t *testing.T) {
	s := NewStub(t)
	c := newClient(t, s)
	ctx := context.Background()

	reg, err := c.Register(ctx, proto.RegisterRequest{PairingCode: "7K3F9Q", Hostname: "vps-1", Version: "0.1.0"})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if reg.RequestID == "" {
		t.Fatalf("RequestID is empty")
	}

	poll, err := c.Poll(ctx, reg.RequestID)
	if err != nil {
		t.Fatalf("Poll (pending): %v", err)
	}
	if poll.Status != "pending" {
		t.Fatalf("Status = %q, want pending", poll.Status)
	}

	s.Approve(reg.RequestID, "ams-1", "tok-123")

	poll, err = c.Poll(ctx, reg.RequestID)
	if err != nil {
		t.Fatalf("Poll (approved): %v", err)
	}
	if poll.Status != "approved" || poll.MonClientID != "ams-1" || poll.Token != "tok-123" {
		t.Fatalf("first approved poll = %+v", poll)
	}

	poll, err = c.Poll(ctx, reg.RequestID)
	if err != nil {
		t.Fatalf("Poll (approved again): %v", err)
	}
	if poll.Token != "" {
		t.Fatalf("second poll handed out the token again: %+v", poll)
	}

	if got := len(s.Requests()); got == 0 {
		t.Fatalf("Requests() is empty")
	}
}

// TestReject checks protocol §2.2's rejected status.
func TestReject(t *testing.T) {
	s := NewStub(t)
	c := newClient(t, s)
	ctx := context.Background()

	reg, err := c.Register(ctx, proto.RegisterRequest{PairingCode: "7K3F9Q"})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	s.Reject(reg.RequestID)

	poll, err := c.Poll(ctx, reg.RequestID)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if poll.Status != "rejected" {
		t.Fatalf("Status = %q, want rejected", poll.Status)
	}
}

// TestExpire checks Poll on an expired request maps to ErrRequestExpired
// through the real api.Client (protocol §2.1).
func TestExpire(t *testing.T) {
	s := NewStub(t)
	c := newClient(t, s)
	ctx := context.Background()

	reg, err := c.Register(ctx, proto.RegisterRequest{PairingCode: "7K3F9Q"})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	s.Expire(reg.RequestID)

	_, err = c.Poll(ctx, reg.RequestID)
	if !errors.Is(err, api.ErrRequestExpired) {
		t.Fatalf("Poll error = %v, want ErrRequestExpired", err)
	}
}

// TestPoll_UnknownRequestIs404 checks an id nobody registered.
func TestPoll_UnknownRequestIs404(t *testing.T) {
	s := NewStub(t)
	c := newClient(t, s)

	_, err := c.Poll(context.Background(), "does-not-exist")
	var se *api.StatusError
	if !errors.As(err, &se) || se.Status != http.StatusNotFound {
		t.Fatalf("Poll error = %v, want 404 StatusError", err)
	}
}

// TestRegisterStatus checks the programmable 429 + Retry-After path
// (protocol §2.1's rate limit).
func TestRegisterStatus(t *testing.T) {
	s := NewStub(t)
	c := newClient(t, s)
	s.RegisterStatus(http.StatusTooManyRequests, 30*time.Second)

	_, err := c.Register(context.Background(), proto.RegisterRequest{PairingCode: "7K3F9Q"})
	var rl *api.RateLimitError
	if !errors.As(err, &rl) {
		t.Fatalf("Register error = %v, want *RateLimitError", err)
	}
	if rl.RetryAfter != 30*time.Second {
		t.Fatalf("RetryAfter = %s, want 30s", rl.RetryAfter)
	}
}

// TestConfig_ServesDocAndNotReady checks SetConfig/SetConfigStatus and the
// default "no config yet" 503 (protocol §4.2, brief's config_not_ready).
func TestConfig_ServesDocAndNotReady(t *testing.T) {
	s := NewStub(t)
	c := newClient(t, s)
	s.Approve("req-1", "ams-1", "tok-1")
	c.Token = "tok-1"
	ctx := context.Background()

	_, err := c.Config(ctx)
	var se *api.StatusError
	if !errors.As(err, &se) || se.Status != http.StatusServiceUnavailable || se.Code != "config_not_ready" {
		t.Fatalf("Config error before SetConfig = %v, want 503 config_not_ready", err)
	}

	doc := &proto.ConfigDoc{ConfigRevision: "rev1", MonClientID: "ams-1", ProbeURL: "https://x/v1/probe"}
	s.SetConfig(doc)
	got, err := c.Config(ctx)
	if err != nil {
		t.Fatalf("Config: %v", err)
	}
	if got.ConfigRevision != "rev1" {
		t.Fatalf("ConfigRevision = %q, want rev1", got.ConfigRevision)
	}

	s.SetConfigStatus(http.StatusInternalServerError)
	_, err = c.Config(ctx)
	if !errors.As(err, &se) || se.Status != http.StatusInternalServerError {
		t.Fatalf("Config error after SetConfigStatus = %v, want 500", err)
	}
}

// TestAuth_TokenStatusOverridesEveryAuthenticatedRoute checks SetTokenStatus
// forces 401/403 on config, heartbeat and probe regardless of the token
// presented (protocol §2.3, §3).
func TestAuth_TokenStatusOverridesEveryAuthenticatedRoute(t *testing.T) {
	s := NewStub(t)
	c := newClient(t, s)
	s.Approve("req-1", "ams-1", "tok-1")
	c.Token = "tok-1"
	ctx := context.Background()

	s.SetTokenStatus(http.StatusUnauthorized)
	if _, err := c.Config(ctx); !errors.Is(err, api.ErrTokenRevoked) {
		t.Fatalf("Config error = %v, want ErrTokenRevoked", err)
	}
	if _, err := c.Heartbeat(ctx, &proto.HeartbeatRequest{MonClientID: "ams-1"}); !errors.Is(err, api.ErrTokenRevoked) {
		t.Fatalf("Heartbeat error = %v, want ErrTokenRevoked", err)
	}

	s.SetTokenStatus(http.StatusForbidden)
	if _, err := c.Config(ctx); !errors.Is(err, api.ErrDisabled) {
		t.Fatalf("Config error = %v, want ErrDisabled", err)
	}

	s.SetTokenStatus(0)
	s.SetConfig(&proto.ConfigDoc{ConfigRevision: "rev1"})
	if _, err := c.Config(ctx); err != nil {
		t.Fatalf("Config after clearing tokenStatus: %v", err)
	}
}

// TestAuth_MissingOrUnknownTokenIs401 checks the default (no
// SetTokenStatus override) bearer check.
func TestAuth_MissingOrUnknownTokenIs401(t *testing.T) {
	s := NewStub(t)
	s.SetConfig(&proto.ConfigDoc{ConfigRevision: "rev1"})
	c := newClient(t, s)
	// No token at all.
	if _, err := c.Config(context.Background()); !errors.Is(err, api.ErrTokenRevoked) {
		t.Fatalf("Config error (no token) = %v, want ErrTokenRevoked", err)
	}
	c.Token = "not-a-real-token"
	if _, err := c.Config(context.Background()); !errors.Is(err, api.ErrTokenRevoked) {
		t.Fatalf("Config error (unknown token) = %v, want ErrTokenRevoked", err)
	}
}

// TestHeartbeat_RecordsAndAcksMaxSeq checks Heartbeats()/SetRevision and
// the ackSeq rule (protocol §5.3: acks everything in the request).
func TestHeartbeat_RecordsAndAcksMaxSeq(t *testing.T) {
	s := NewStub(t)
	s.Approve("req-1", "ams-1", "tok-1")
	s.SetRevision("rev-2")
	c := newClient(t, s)
	c.Token = "tok-1"

	hb := &proto.HeartbeatRequest{
		MonClientID: "ams-1",
		Cycles: []proto.Cycle{
			{Seq: 10}, {Seq: 12}, {Seq: 11},
		},
	}
	resp, err := c.Heartbeat(context.Background(), hb)
	if err != nil {
		t.Fatalf("Heartbeat: %v", err)
	}
	if resp.AckSeq != 12 {
		t.Fatalf("AckSeq = %d, want 12", resp.AckSeq)
	}
	if resp.ConfigRevision != "rev-2" {
		t.Fatalf("ConfigRevision = %q, want rev-2", resp.ConfigRevision)
	}

	got := s.Heartbeats()
	if len(got) != 1 || got[0].MonClientID != "ams-1" {
		t.Fatalf("Heartbeats() = %+v", got)
	}
}

// TestHeartbeat_FailNextAndDropNext checks the injected-failure knobs used
// to exercise the unverified-cycle path (protocol §5.3, §6).
func TestHeartbeat_FailNextAndDropNext(t *testing.T) {
	s := NewStub(t)
	s.Approve("req-1", "ams-1", "tok-1")
	c := newClient(t, s)
	c.Token = "tok-1"

	s.FailNextHeartbeats(1, http.StatusInternalServerError)
	_, err := c.Heartbeat(context.Background(), &proto.HeartbeatRequest{MonClientID: "ams-1"})
	var se *api.StatusError
	if !errors.As(err, &se) || se.Status != http.StatusInternalServerError {
		t.Fatalf("Heartbeat error = %v, want 500", err)
	}

	// The failure was consumed; the next call succeeds.
	if _, err := c.Heartbeat(context.Background(), &proto.HeartbeatRequest{MonClientID: "ams-1"}); err != nil {
		t.Fatalf("Heartbeat after failN consumed: %v", err)
	}

	s.DropNextHeartbeats(1)
	_, err = c.Heartbeat(context.Background(), &proto.HeartbeatRequest{MonClientID: "ams-1"})
	var netErr *api.NetError
	if !errors.As(err, &netErr) {
		t.Fatalf("Heartbeat error = %v (%T), want *NetError", err, err)
	}
}

// TestProbe_EchoAndWrongNonce checks the plain echo and SetProbeNonce's
// forced mismatch (protocol §5.2, spec §5's http_error path).
func TestProbe_EchoAndWrongNonce(t *testing.T) {
	s := NewStub(t)
	s.Approve("req-1", "ams-1", "tok-1")

	hc := s.HTTPClient()
	req, err := http.NewRequest(http.MethodGet, s.URL()+"/v1/probe?target=xray:12:proxy&n=abc123", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer tok-1")
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	s.SetProbeNonce("wrong-nonce")
	req2, _ := http.NewRequest(http.MethodGet, s.URL()+"/v1/probe?target=xray:12:proxy&n=abc123", nil)
	req2.Header.Set("Authorization", "Bearer tok-1")
	resp2, err := hc.Do(req2)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp2.Body.Close()
	var echo proto.ProbeEcho
	if err := decodeJSON(resp2, &echo); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if echo.Nonce != "wrong-nonce" {
		t.Fatalf("Nonce = %q, want wrong-nonce", echo.Nonce)
	}
}

// TestProbe_HangNextForcesTimeout checks HangNextProbes actually holds the
// request until the caller's own context gives up.
func TestProbe_HangNextForcesTimeout(t *testing.T) {
	s := NewStub(t)
	s.Approve("req-1", "ams-1", "tok-1")
	s.HangNextProbes(1)

	hc := s.HTTPClient()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, s.URL()+"/v1/probe?target=xray:12:proxy&n=abc123", nil)
	req.Header.Set("Authorization", "Bearer tok-1")

	start := time.Now()
	_, err := hc.Do(req)
	if err == nil {
		t.Fatalf("Do succeeded, want a timeout error")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("took %s, want it to fail promptly at the context deadline", elapsed)
	}
}
