package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/SBKubric/3ax-ui-monitoring/internal/state"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
)

// stubEngine is a scriptable stand-in for *state.Engine: the handler's job
// is decoding, authorising and mapping the engine's outcome onto a status.
type stubEngine struct {
	resp *state.HeartbeatResponse
	err  error

	seenClient string
	seen       *state.HeartbeatRequest
}

func (s *stubEngine) Heartbeat(_ context.Context, mc *store.MonClient, hb *state.HeartbeatRequest) (*state.HeartbeatResponse, error) {
	s.seenClient = mc.Id
	s.seen = hb
	return s.resp, s.err
}

func newHeartbeatTestServer(auth stubAuthenticator, eng *stubEngine) *Server {
	s := New()
	HeartbeatRoutes(s.V1, auth, eng)
	return s
}

func postHeartbeat(s *Server, token, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/v1/heartbeat", strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.Engine.ServeHTTP(rec, req)
	return rec
}

// TestHeartbeat_AppliesAndAnswers is protocol §5.3's happy path: the body
// reaches the engine as sent, and the engine's answer is the response.
func TestHeartbeat_AppliesAndAnswers(t *testing.T) {
	eng := &stubEngine{resp: &state.HeartbeatResponse{ConfigRevision: "3a91c0de77b1f2e4", ServerTs: 1757721620000, AckSeq: 1441}}
	s := newHeartbeatTestServer(stubAuthenticator{client: &store.MonClient{Id: "ams-1"}}, eng)

	rec := postHeartbeat(s, "tok", `{"monClientId":"ams-1","configRevision":"old","client":{"version":"0.1.0"},
		"cycles":[{"seq":1441,"ts":1757721600000,"unverified":false,"results":[
		  {"inboundKind":"xray","inboundId":12,"path":"proxy","ok":true,"tlsMs":47,"reason":null}]}],
		"somethingNew":true}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	var got state.HeartbeatResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode body: %v (%s)", err, rec.Body.String())
	}
	if got.AckSeq != 1441 || got.ConfigRevision != "3a91c0de77b1f2e4" || got.ServerTs != 1757721620000 {
		t.Fatalf("body = %+v, want the engine's answer verbatim", got)
	}
	if eng.seenClient != "ams-1" {
		t.Fatalf("engine got mon-client %q, want the authenticated one", eng.seenClient)
	}
	if len(eng.seen.Cycles) != 1 || len(eng.seen.Cycles[0].Results) != 1 || !eng.seen.Cycles[0].Results[0].Ok {
		t.Fatalf("engine got %+v, want the decoded cycle (unknown fields tolerated)", eng.seen)
	}
}

// TestHeartbeat_RequiresToken checks the route is actually behind
// RequireClientToken (protocol §3).
func TestHeartbeat_RequiresToken(t *testing.T) {
	eng := &stubEngine{resp: &state.HeartbeatResponse{}}
	s := newHeartbeatTestServer(stubAuthenticator{client: &store.MonClient{Id: "ams-1"}}, eng)

	rec := postHeartbeat(s, "", `{"monClientId":"ams-1"}`)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if eng.seen != nil {
		t.Fatal("engine was called for an unauthenticated heartbeat")
	}
}

// TestHeartbeat_RejectsAnotherClientsId is the ownership check: the body's
// monClientId must be the token's own.
func TestHeartbeat_RejectsAnotherClientsId(t *testing.T) {
	eng := &stubEngine{resp: &state.HeartbeatResponse{}}
	s := newHeartbeatTestServer(stubAuthenticator{client: &store.MonClient{Id: "ams-1"}}, eng)

	rec := postHeartbeat(s, "tok", `{"monClientId":"msk-1"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body=%s", rec.Code, rec.Body.String())
	}
	if code := errorCode(t, rec.Body.Bytes()); code != "bad_request" {
		t.Fatalf("error code = %q, want bad_request", code)
	}
	if eng.seen != nil {
		t.Fatal("engine was called for a heartbeat about another mon-client")
	}
}

// TestHeartbeat_RejectsGarbage covers the decode failure code.
func TestHeartbeat_RejectsGarbage(t *testing.T) {
	eng := &stubEngine{resp: &state.HeartbeatResponse{}}
	s := newHeartbeatTestServer(stubAuthenticator{client: &store.MonClient{Id: "ams-1"}}, eng)

	rec := postHeartbeat(s, "tok", `{"monClientId":`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if code := errorCode(t, rec.Body.Bytes()); code != "invalid_body" {
		t.Fatalf("error code = %q, want invalid_body", code)
	}
}

// TestHeartbeat_RejectsAnOversizedBody proves the 1 MiB cap is enforced
// rather than merely documented: a body past it is refused, not buffered.
func TestHeartbeat_RejectsAnOversizedBody(t *testing.T) {
	eng := &stubEngine{resp: &state.HeartbeatResponse{}}
	s := newHeartbeatTestServer(stubAuthenticator{client: &store.MonClient{Id: "ams-1"}}, eng)

	huge := `{"monClientId":"ams-1","configRevision":"` + strings.Repeat("a", maxHeartbeatBody+1) + `"}`
	rec := postHeartbeat(s, "tok", huge)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for a body over the cap", rec.Code)
	}
	if eng.seen != nil {
		t.Fatal("engine was called with an oversized body")
	}
}

// TestHeartbeat_EngineFailureIsA500 checks a mon-server-side failure keeps
// its detail out of the response (the mon-client just retries).
func TestHeartbeat_EngineFailureIsA500(t *testing.T) {
	eng := &stubEngine{err: errors.New("database is locked")}
	s := newHeartbeatTestServer(stubAuthenticator{client: &store.MonClient{Id: "ams-1"}}, eng)

	rec := postHeartbeat(s, "tok", `{"monClientId":"ams-1"}`)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "database is locked") {
		t.Fatalf("body leaks the internal error: %s", rec.Body.String())
	}
}

// errorCode pulls the protocol's error code out of a failure body.
func errorCode(t *testing.T, body []byte) string {
	t.Helper()
	var e errorBody
	if err := json.Unmarshal(body, &e); err != nil {
		t.Fatalf("decode error body: %v (%s)", err, body)
	}
	return e.Error
}
