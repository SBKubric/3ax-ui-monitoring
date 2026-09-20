package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
	"github.com/SBKubric/3ax-ui-monitoring/internal/registry"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
)

// newRegisterTestServer wires a fresh Registry onto a fresh gin.Engine's V1
// group, over a temp-file store and a Fake clock so TTL/rate-limit tests
// drive time deterministically instead of sleeping.
func newRegisterTestServer(t *testing.T) (*Server, *registry.Registry, *clock.Fake) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	clk := clock.NewFake(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	st.Clock = clk

	r := registry.New(st, clk)
	s := New()
	RegisterRoutes(s.V1, r)
	return s, r, clk
}

func doRegister(t *testing.T, s *Server, remoteAddr string, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/register", bytes.NewReader(b))
	req.RemoteAddr = remoteAddr
	rec := httptest.NewRecorder()
	s.Engine.ServeHTTP(rec, req)
	return rec
}

func doPoll(t *testing.T, s *Server, requestID string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/v1/register/"+requestID, nil)
	rec := httptest.NewRecorder()
	s.Engine.ServeHTTP(rec, req)
	return rec
}

// TestHandleRegister_Success checks the protocol §2.1 happy path: a valid
// pairing code gets a 202 with requestId/pollAfter/expiresAt, not wrapped in
// any admin-UI-style envelope.
func TestHandleRegister_Success(t *testing.T) {
	s, _, _ := newRegisterTestServer(t)

	rec := doRegister(t, s, "1.2.3.4:5555", map[string]any{
		"pairingCode": "ABCDEF", "hostname": "vps-ams-1", "version": "0.1.0", "publicIp": "203.0.113.5",
	})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202, body=%s", rec.Code, rec.Body.String())
	}

	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}
	if _, ok := got["requestId"].(string); !ok || got["requestId"] == "" {
		t.Fatalf("body = %v, want a non-empty string requestId", got)
	}
	if pollAfter, ok := got["pollAfter"].(float64); !ok || pollAfter != 10000 {
		t.Fatalf("pollAfter = %v, want 10000", got["pollAfter"])
	}
	if _, ok := got["expiresAt"].(float64); !ok {
		t.Fatalf("body = %v, want a numeric expiresAt", got)
	}
}

// TestHandleRegister_InvalidPairingCode checks that a malformed pairing
// code is a 400 invalid_body, the protocol's generic client-error code.
func TestHandleRegister_InvalidPairingCode(t *testing.T) {
	s, _, _ := newRegisterTestServer(t)

	rec := doRegister(t, s, "1.2.3.4:5555", map[string]any{"pairingCode": "not-valid"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"error":"invalid_body"`) {
		t.Fatalf("body = %q, want invalid_body error code", rec.Body.String())
	}
}

// TestHandleRegister_RateLimited checks that the second request from the
// same IP within the throttle window is a 429 too_many_requests carrying a
// Retry-After header (protocol §2.1).
func TestHandleRegister_RateLimited(t *testing.T) {
	s, _, _ := newRegisterTestServer(t)

	first := doRegister(t, s, "9.9.9.9:1", map[string]any{"pairingCode": "ABCDEF"})
	if first.Code != http.StatusAccepted {
		t.Fatalf("first status = %d, want 202, body=%s", first.Code, first.Body.String())
	}

	second := doRegister(t, s, "9.9.9.9:2", map[string]any{"pairingCode": "ABCDEF"})
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("second status = %d, want 429, body=%s", second.Code, second.Body.String())
	}
	if !strings.Contains(second.Body.String(), `"error":"too_many_requests"`) {
		t.Fatalf("body = %q, want too_many_requests error code", second.Body.String())
	}
	if ra := second.Header().Get("Retry-After"); ra != "60" {
		t.Fatalf("Retry-After = %q, want 60", ra)
	}
}

// TestHandlePoll_UnknownRequestID checks protocol §2.1's "без деталей": an
// unrecognised requestId is exactly {"error":"not_found","message":...},
// carrying nothing that would let a caller distinguish "never existed" from
// "belongs to someone else".
func TestHandlePoll_UnknownRequestID(t *testing.T) {
	s, _, _ := newRegisterTestServer(t)

	rec := doPoll(t, s, "does-not-exist")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404, body=%s", rec.Code, rec.Body.String())
	}

	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}
	if len(got) != 2 || got["error"] != "not_found" {
		t.Fatalf("body = %v, want exactly {error: not_found, message: ...}", got)
	}
}

// TestHandlePoll_Expired checks the TTL path end to end through the HTTP
// layer: after the request's 5 minutes are up, polling it is 410
// request_expired.
func TestHandlePoll_Expired(t *testing.T) {
	s, _, clk := newRegisterTestServer(t)

	rec := doRegister(t, s, "1.2.3.4:1", map[string]any{"pairingCode": "ABCDEF"})
	var reg map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &reg); err != nil {
		t.Fatalf("unmarshal register body: %v", err)
	}
	requestID := reg["requestId"].(string)

	clk.Advance(5*time.Minute + time.Second)

	poll := doPoll(t, s, requestID)
	if poll.Code != http.StatusGone {
		t.Fatalf("status = %d, want 410, body=%s", poll.Code, poll.Body.String())
	}
	if !strings.Contains(poll.Body.String(), `"error":"request_expired"`) {
		t.Fatalf("body = %q, want request_expired error code", poll.Body.String())
	}
}

// TestHandlePoll_ApprovedTokenOnce checks the HTTP-level view of the
// one-time token hand-off: the first poll after Approve carries a token,
// the second the same status with no token field at all.
func TestHandlePoll_ApprovedTokenOnce(t *testing.T) {
	s, r, _ := newRegisterTestServer(t)

	rec := doRegister(t, s, "1.2.3.4:1", map[string]any{"pairingCode": "ABCDEF"})
	var reg map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &reg); err != nil {
		t.Fatalf("unmarshal register body: %v", err)
	}
	requestID := reg["requestId"].(string)

	mc, err := r.Approve(t.Context(), requestID, registry.ApproveInput{Name: "Test"})
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}

	first := doPoll(t, s, requestID)
	var firstBody map[string]any
	if err := json.Unmarshal(first.Body.Bytes(), &firstBody); err != nil {
		t.Fatalf("unmarshal first poll: %v", err)
	}
	if firstBody["status"] != "approved" || firstBody["monClientId"] != mc.Id || firstBody["token"] == "" || firstBody["token"] == nil {
		t.Fatalf("first poll body = %v, want approved with id %q and a token", firstBody, mc.Id)
	}

	second := doPoll(t, s, requestID)
	var secondBody map[string]any
	if err := json.Unmarshal(second.Body.Bytes(), &secondBody); err != nil {
		t.Fatalf("unmarshal second poll: %v", err)
	}
	if secondBody["status"] != "approved" {
		t.Fatalf("second poll status = %v, want approved", secondBody["status"])
	}
	if _, present := secondBody["token"]; present {
		t.Fatalf("second poll body = %v, want no token field", secondBody)
	}
}

// TestHandleRegister_BodyTooLarge checks that a body over registerMaxBodyBytes
// is 413 batch_too_large (the panel contract's own code for the same
// condition, mirrored per protocol §1), not a generic 400.
func TestHandleRegister_BodyTooLarge(t *testing.T) {
	s, _, _ := newRegisterTestServer(t)

	huge := strings.Repeat("a", registerMaxBodyBytes+1)
	body := `{"pairingCode":"ABCDEF","hostname":"` + huge + `"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/register", strings.NewReader(body))
	rec := httptest.NewRecorder()
	s.Engine.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413, body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"error":"batch_too_large"`) {
		t.Fatalf("body = %q, want batch_too_large error code", rec.Body.String())
	}
}

// TestHandleRegister_EmptyBodyIsBadRequest checks that an empty body is a
// plain 400 invalid_body — protocol §1's generic client-error code — with
// no special-cased "treat as zero values" carve-out for io.EOF.
func TestHandleRegister_EmptyBodyIsBadRequest(t *testing.T) {
	s, _, _ := newRegisterTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/v1/register", strings.NewReader(""))
	rec := httptest.NewRecorder()
	s.Engine.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"error":"invalid_body"`) {
		t.Fatalf("body = %q, want invalid_body error code", rec.Body.String())
	}
}

// TestFailRegister_InternalErrorDoesNotLeakDetails checks that an internal
// (non-sentinel) error from Register/Poll never reaches the response body —
// it is logged instead, and the caller gets a generic 500.
func TestFailRegister_InternalErrorDoesNotLeakDetails(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/register", nil)

	dbErr := fmt.Errorf("register: %w", errors.New("database is locked (5) (SQLITE_BUSY)"))
	failRegister(c, dbErr)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500, body=%s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "SQLITE_BUSY") || strings.Contains(w.Body.String(), "database is locked") {
		t.Fatalf("body = %q, leaked internal error detail", w.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}
	if got["error"] != "internal" || got["message"] != "internal error" {
		t.Fatalf("body = %v, want {error: internal, message: internal error}", got)
	}
}
