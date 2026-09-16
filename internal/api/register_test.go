package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
)

// registerTestTime is where the fake clock of these tests sits.
var registerTestTime = time.Date(2025, 9, 13, 10, 0, 0, 0, time.UTC)

// registerStub is a RegistrationService whose two answers the test sets.
type registerStub struct {
	submitted RegistrationSubmit
	result    RegistrationSubmitted
	submitErr error

	polled  string
	status  RegistrationStatus
	pollErr error
}

func (s *registerStub) Submit(_ context.Context, req RegistrationSubmit) (RegistrationSubmitted, error) {
	s.submitted = req
	return s.result, s.submitErr
}

func (s *registerStub) Poll(_ context.Context, requestID string) (RegistrationStatus, error) {
	s.polled = requestID
	return s.status, s.pollErr
}

// registerStubRateLimit is a refusal that carries its own Retry-After hint,
// the way the registry's RateLimitError does.
type registerStubRateLimit struct{ wait time.Duration }

func (e registerStubRateLimit) Error() string             { return "too many registration requests" }
func (e registerStubRateLimit) Unwrap() error             { return ErrRegistrationRateLimited }
func (e registerStubRateLimit) RetryAfter() time.Duration { return e.wait }
func registerTestHandler(svc RegistrationService) http.Handler {
	s := New(nil, clock.NewFake(registerTestTime), slog.New(slog.DiscardHandler))
	RegisterRegistrationRoutes(s, svc)
	return s.Handler()
}

// registerDo runs one request against the registration routes.
func registerDo(t *testing.T, svc RegistrationService, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	registerTestHandler(svc).ServeHTTP(rec, req)
	return rec
}

// registerPost builds a POST /v1/register with body as its payload.
func registerPost(body string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/v1/register", strings.NewReader(body))
	req.RemoteAddr = "203.0.113.5:54321"
	req.Header.Set("Content-Type", "application/json")
	return req
}

// registerBodyOf decodes a JSON response body into a map, so a test can assert
// on the exact set of keys.
func registerBodyOf(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	return body
}

func TestRegisterPostAcceptsARequest(t *testing.T) {
	svc := &registerStub{result: RegistrationSubmitted{
		RequestID:   "kZ0P6Vb1Tn2_Xq8Qq7Lm0A",
		PollAfterMS: 10_000,
		ExpiresAt:   clock.MS(registerTestTime.Add(5 * time.Minute)),
	}}

	rec := registerDo(t, svc, registerPost(`{"pairingCode":"7K3F9Q","hostname":"vps-ams-1","version":"0.1.0","publicIp":"203.0.113.9"}`))

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusAccepted, rec.Body)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json; charset=utf-8" {
		t.Errorf("content type = %q", got)
	}
	body := registerBodyOf(t, rec)
	if body["requestId"] != "kZ0P6Vb1Tn2_Xq8Qq7Lm0A" {
		t.Errorf("requestId = %v", body["requestId"])
	}
	if body["pollAfter"] != float64(10_000) {
		t.Errorf("pollAfter = %v, want 10000", body["pollAfter"])
	}
	if body["expiresAt"] != float64(clock.MS(registerTestTime.Add(5*time.Minute))) {
		t.Errorf("expiresAt = %v", body["expiresAt"])
	}

	want := RegistrationSubmit{
		PairingCode: "7K3F9Q",
		Hostname:    "vps-ams-1",
		Version:     "0.1.0",
		PublicIP:    "203.0.113.9",
		RemoteIP:    "203.0.113.5",
	}
	if svc.submitted != want {
		t.Errorf("the service was given %+v, want %+v (the remote address, not the reported one)", svc.submitted, want)
	}
}

func TestRegisterPostRefusals(t *testing.T) {
	tests := []struct {
		name           string
		body           string
		err            error
		wantStatus     int
		wantCode       string
		wantRetryAfter string
	}{
		{
			name:       "a malformed body",
			body:       `{"pairingCode":`,
			wantStatus: http.StatusBadRequest,
			wantCode:   ErrCodeInvalidBody,
		},
		{
			name:       "an empty body",
			body:       ``,
			wantStatus: http.StatusBadRequest,
			wantCode:   ErrCodeInvalidBody,
		},
		{
			name:       "a body that is not an object",
			body:       `"7K3F9Q"`,
			wantStatus: http.StatusBadRequest,
			wantCode:   ErrCodeInvalidBody,
		},
		{
			name:       "a pairing code the service refuses",
			body:       `{"pairingCode":"nope"}`,
			err:        ErrRegistrationInvalid,
			wantStatus: http.StatusBadRequest,
			wantCode:   ErrCodeInvalidBody,
		},
		{
			name:           "a rate limit with a hint of its own",
			body:           `{"pairingCode":"7K3F9Q"}`,
			err:            registerStubRateLimit{wait: 42 * time.Second},
			wantStatus:     http.StatusTooManyRequests,
			wantCode:       ErrCodeTooManyRequests,
			wantRetryAfter: "42",
		},
		{
			name:           "a hint of less than a second still asks for one",
			body:           `{"pairingCode":"7K3F9Q"}`,
			err:            registerStubRateLimit{wait: 200 * time.Millisecond},
			wantStatus:     http.StatusTooManyRequests,
			wantCode:       ErrCodeTooManyRequests,
			wantRetryAfter: "1",
		},
		{
			name:           "a fraction of a second is rounded up",
			body:           `{"pairingCode":"7K3F9Q"}`,
			err:            registerStubRateLimit{wait: 90_500 * time.Millisecond},
			wantStatus:     http.StatusTooManyRequests,
			wantCode:       ErrCodeTooManyRequests,
			wantRetryAfter: "91",
		},
		{
			name:           "a rate limit with no hint falls back to a minute",
			body:           `{"pairingCode":"7K3F9Q"}`,
			err:            ErrRegistrationRateLimited,
			wantStatus:     http.StatusTooManyRequests,
			wantCode:       ErrCodeTooManyRequests,
			wantRetryAfter: "60",
		},
		{
			name:       "a service that is broken",
			body:       `{"pairingCode":"7K3F9Q"}`,
			err:        errors.New("database is locked"),
			wantStatus: http.StatusInternalServerError,
			wantCode:   ErrCodeInternal,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := registerDo(t, &registerStub{submitErr: tc.err}, registerPost(tc.body))

			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tc.wantStatus, rec.Body)
			}
			if got := registerBodyOf(t, rec)["error"]; got != tc.wantCode {
				t.Errorf("error = %v, want %q", got, tc.wantCode)
			}
			if got := rec.Header().Get("Retry-After"); got != tc.wantRetryAfter {
				t.Errorf("Retry-After = %q, want %q", got, tc.wantRetryAfter)
			}
			if tc.wantStatus == http.StatusInternalServerError {
				if strings.Contains(rec.Body.String(), "database is locked") {
					t.Error("the internal error reached the mon-client")
				}
			}
		})
	}
}

func TestRegisterGetStatusShapes(t *testing.T) {
	tests := []struct {
		name   string
		status RegistrationStatus
		want   map[string]any
	}{
		{
			name:   "pending",
			status: RegistrationStatus{Status: "pending"},
			want:   map[string]any{"status": "pending"},
		},
		{
			name:   "approved with the token",
			status: RegistrationStatus{Status: "approved", MonClientID: "ams-1", Token: "s3cret"},
			want:   map[string]any{"status": "approved", "monClientId": "ams-1", "token": "s3cret"},
		},
		{
			name:   "approved once the token has been collected",
			status: RegistrationStatus{Status: "approved", MonClientID: "ams-1"},
			want:   map[string]any{"status": "approved", "monClientId": "ams-1"},
		},
		{
			name:   "rejected",
			status: RegistrationStatus{Status: "rejected"},
			want:   map[string]any{"status": "rejected"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc := &registerStub{status: tc.status}
			rec := registerDo(t, svc, httptest.NewRequest(http.MethodGet, "/v1/register/abc123", nil))

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body)
			}
			if svc.polled != "abc123" {
				t.Errorf("the service was asked for %q, want the path value", svc.polled)
			}
			body := registerBodyOf(t, rec)
			if len(body) != len(tc.want) {
				t.Fatalf("body = %v, want exactly %v", body, tc.want)
			}
			for key, value := range tc.want {
				if body[key] != value {
					t.Errorf("%s = %v, want %v", key, body[key], value)
				}
			}
		})
	}
}

func TestRegisterGetUnknownIDIsABare404(t *testing.T) {
	rec := registerDo(t, &registerStub{pollErr: ErrRegistrationNotFound},
		httptest.NewRequest(http.MethodGet, "/v1/register/whatever", nil))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	body, err := io.ReadAll(rec.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if len(body) != 0 {
		t.Errorf("body = %q, want nothing: an unknown requestId gets no detail", body)
	}
}

func TestRegisterGetExpiredRequest(t *testing.T) {
	rec := registerDo(t, &registerStub{pollErr: ErrRegistrationExpired},
		httptest.NewRequest(http.MethodGet, "/v1/register/abc123", nil))

	if rec.Code != http.StatusGone {
		t.Fatalf("status = %d, want 410: %s", rec.Code, rec.Body)
	}
	if got := registerBodyOf(t, rec)["error"]; got != ErrCodeRequestExpired {
		t.Errorf("error = %v, want %q", got, ErrCodeRequestExpired)
	}
}

func TestRegisterGetBrokenService(t *testing.T) {
	rec := registerDo(t, &registerStub{pollErr: errors.New("database is locked")},
		httptest.NewRequest(http.MethodGet, "/v1/register/abc123", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: %s", rec.Code, rec.Body)
	}
	if got := registerBodyOf(t, rec)["error"]; got != ErrCodeInternal {
		t.Errorf("error = %v, want %q", got, ErrCodeInternal)
	}
	if strings.Contains(rec.Body.String(), "database is locked") {
		t.Error("the internal error reached the mon-client")
	}
}
