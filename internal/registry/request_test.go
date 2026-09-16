package registry

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/api"
	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
)

func TestSubmitChecksThePairingCode(t *testing.T) {
	tests := []struct {
		name string
		code string
		want error
	}{
		{name: "six of the alphabet", code: "7K3F9Q"},
		{name: "letters only", code: "ABCDEF"},
		{name: "digits only", code: "234567"},
		{name: "lowercase", code: "7k3f9q", want: ErrInvalidPairingCode},
		{name: "too short", code: "7K3F9", want: ErrInvalidPairingCode},
		{name: "too long", code: "7K3F9QQ", want: ErrInvalidPairingCode},
		{name: "empty", code: "", want: ErrInvalidPairingCode},
		{name: "zero is not in the alphabet", code: "7K3F90", want: ErrInvalidPairingCode},
		{name: "one is not in the alphabet", code: "7K3F91", want: ErrInvalidPairingCode},
		{name: "punctuation", code: "7K3F9-", want: ErrInvalidPairingCode},
		{name: "not ascii", code: "7K3F9Ж", want: ErrInvalidPairingCode},
		{name: "surrounding whitespace is trimmed off", code: " 7K3F9Q\n"},
		{name: "a space inside is not", code: "7K 3F9", want: ErrInvalidPairingCode},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reg, _, _ := newTestRegistry(t)
			_, err := reg.Submit(context.Background(), SubmitRequest{
				PairingCode: tc.code,
				Hostname:    "vps-ams-1",
				RemoteIP:    "203.0.113.5",
			})
			if tc.want == nil {
				if err != nil {
					t.Fatalf("Submit(%q) = %v, want it accepted", tc.code, err)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("Submit(%q) = %v, want %v", tc.code, err, tc.want)
			}
			if !errors.Is(err, ErrInvalidRequest) {
				t.Errorf("Submit(%q) does not wrap ErrInvalidRequest", tc.code)
			}
		})
	}
}

func TestSubmitAnswersWithAPollingSecretAndADeadline(t *testing.T) {
	reg, st, _ := newTestRegistry(t)

	res := submit(t, reg, "203.0.113.5", "7K3F9Q")

	if res.PollAfterMS != 10_000 {
		t.Errorf("pollAfter = %d, want 10000", res.PollAfterMS)
	}
	if want := clock.MS(testTime.Add(5 * time.Minute)); res.ExpiresAt != want {
		t.Errorf("expiresAt = %d, want %d (now + 5m)", res.ExpiresAt, want)
	}
	raw, err := base64.RawURLEncoding.DecodeString(res.RequestID)
	if err != nil {
		t.Fatalf("requestId %q is not unpadded base64url: %v", res.RequestID, err)
	}
	if len(raw) != 16 {
		t.Errorf("requestId carries %d bytes, want 16 (128 bits)", len(raw))
	}

	row := requestRow(t, st, res.RequestID)
	if row.Status != store.RequestPending {
		t.Errorf("status = %q, want %q", row.Status, store.RequestPending)
	}
	if row.ApprovedToken != "" {
		t.Error("a pending request must not carry a token")
	}
	if row.PairingCode != "7K3F9Q" || row.Hostname != "vps-ams-1" || row.RemoteIP != "203.0.113.5" {
		t.Errorf("stored request = %+v, want the submitted values", row)
	}
}

func TestSubmitRequestIDsAreDistinct(t *testing.T) {
	reg, _, fake := newTestRegistry(t)

	seen := map[string]bool{}
	for i := range 5 {
		res := submit(t, reg, fmt.Sprintf("203.0.113.%d", i), "7K3F9Q")
		if seen[res.RequestID] {
			t.Fatalf("requestId %q was issued twice", res.RequestID)
		}
		seen[res.RequestID] = true
		fake.Advance(time.Second)
	}
}

func TestSubmitAllowsOneRequestPerMinutePerIP(t *testing.T) {
	reg, _, fake := newTestRegistry(t)
	const ip = "203.0.113.5"

	submit(t, reg, ip, "7K3F9Q")

	fake.Advance(30 * time.Second)
	_, err := reg.Submit(context.Background(), SubmitRequest{PairingCode: "AAAAAA", RemoteIP: ip})
	if !errors.Is(err, ErrIPRateLimited) {
		t.Fatalf("second request within the minute = %v, want ErrIPRateLimited", err)
	}
	if !errors.Is(err, ErrRateLimited) {
		t.Error("the rate limit error does not wrap ErrRateLimited")
	}
	var limited *RateLimitError
	if !errors.As(err, &limited) {
		t.Fatalf("error %v carries no Retry-After hint", err)
	}
	if got := limited.RetryAfter(); got <= 0 || got > time.Minute {
		t.Errorf("Retry-After = %s, want a hint inside the minute", got)
	}

	// Another box behind another address is unaffected.
	submit(t, reg, "203.0.113.6", "BBBBBB")

	fake.Advance(31 * time.Second)
	submit(t, reg, ip, "CCCCCC")
}

func TestSubmitAllowsThreePendingPerIP(t *testing.T) {
	reg, _, fake := newTestRegistry(t)
	const ip = "203.0.113.5"

	for range MaxPendingPerIP {
		submit(t, reg, ip, "7K3F9Q")
		fake.Advance(61 * time.Second)
	}

	_, err := reg.Submit(context.Background(), SubmitRequest{PairingCode: "7K3F9Q", RemoteIP: ip})
	if !errors.Is(err, ErrTooManyPendingForIP) {
		t.Fatalf("fourth pending request = %v, want ErrTooManyPendingForIP", err)
	}
	var limited *RateLimitError
	if !errors.As(err, &limited) || limited.RetryAfter() <= 0 {
		t.Fatalf("error %v carries no usable Retry-After hint", err)
	}

	// A different address still gets in: the limit is per IP.
	submit(t, reg, "198.51.100.7", "7K3F9Q")

	// Once the oldest request of the IP has expired, the box may file again.
	fake.Advance(5 * time.Minute)
	submit(t, reg, ip, "7K3F9Q")
}

func TestSubmitAllowsTwentyPendingRequestsOverall(t *testing.T) {
	reg, _, _ := newTestRegistry(t)

	for i := range MaxPendingTotal {
		submit(t, reg, fmt.Sprintf("203.0.113.%d", i), "7K3F9Q")
	}

	_, err := reg.Submit(context.Background(), SubmitRequest{PairingCode: "7K3F9Q", RemoteIP: "198.51.100.1"})
	if !errors.Is(err, ErrTooManyPendingGlobal) {
		t.Fatalf("twenty-first pending request = %v, want ErrTooManyPendingGlobal", err)
	}
	var limited *RateLimitError
	if !errors.As(err, &limited) || limited.RetryAfter() <= 0 {
		t.Fatalf("error %v carries no usable Retry-After hint", err)
	}
}

func TestSubmitCountsOnlyLiveRequestsAgainstTheGlobalLimit(t *testing.T) {
	reg, _, fake := newTestRegistry(t)

	for i := range MaxPendingTotal {
		submit(t, reg, fmt.Sprintf("203.0.113.%d", i), "7K3F9Q")
	}

	// The queue is full, so a fresh address is refused. Without this the test
	// would pass even if the global limit were never enforced at all.
	_, err := reg.Submit(context.Background(), SubmitRequest{
		PairingCode: "7K3F9Q", Hostname: "vps-full", Version: "0.1.0", RemoteIP: "198.51.100.1",
	})
	if !errors.Is(err, ErrRateLimited) || !errors.Is(err, ErrTooManyPendingGlobal) {
		t.Fatalf("submit with the queue full = %v, want the global pending limit", err)
	}

	// Every one of them times out, so the queue is empty again and the same
	// address gets in.
	fake.Advance(RequestTTL + time.Second)
	submit(t, reg, "198.51.100.1", "7K3F9Q")
}

func TestPollFollowsTheRequestLifetime(t *testing.T) {
	reg, st, fake := newTestRegistry(t)
	res := submit(t, reg, "203.0.113.5", "7K3F9Q")

	fake.Advance(4 * time.Minute)
	if got := poll(t, reg, res.RequestID); got.Status != store.RequestPending {
		t.Fatalf("status after four minutes = %q, want %q", got.Status, store.RequestPending)
	}

	fake.Advance(time.Minute + time.Second)
	if _, err := reg.Poll(context.Background(), res.RequestID); !errors.Is(err, ErrRequestExpired) {
		t.Fatalf("poll after five minutes = %v, want ErrRequestExpired", err)
	}
	if got := requestRow(t, st, res.RequestID).Status; got != store.RequestExpired {
		t.Errorf("stored status = %q, want %q: the row must not stay pending", got, store.RequestExpired)
	}
	// It stays expired on every later poll.
	if _, err := reg.Poll(context.Background(), res.RequestID); !errors.Is(err, ErrRequestExpired) {
		t.Fatalf("second poll after expiry = %v, want ErrRequestExpired", err)
	}
}

func TestPollUnknownRequestIsNotFound(t *testing.T) {
	reg, _, _ := newTestRegistry(t)
	submit(t, reg, "203.0.113.5", "7K3F9Q")

	for _, id := range []string{"", "nope", "0000000000000000000000"} {
		if _, err := reg.Poll(context.Background(), id); !errors.Is(err, ErrRequestNotFound) {
			t.Errorf("Poll(%q) = %v, want ErrRequestNotFound", id, err)
		}
	}
}

func TestPollHandsTheTokenOutExactlyOnce(t *testing.T) {
	reg, st, _ := newTestRegistry(t)
	res := submit(t, reg, "203.0.113.5", "7K3F9Q")
	approved := approve(t, reg, res.RequestID, ApproveInput{Name: "AMS 1", Region: "eu"})

	first := poll(t, reg, res.RequestID)
	if first.Status != store.RequestApproved {
		t.Fatalf("status = %q, want %q", first.Status, store.RequestApproved)
	}
	if first.MonClientID != approved.MonClientID {
		t.Errorf("monClientId = %q, want %q", first.MonClientID, approved.MonClientID)
	}
	if first.Token == "" {
		t.Fatal("the first poll returned no token")
	}
	if got := requestRow(t, st, res.RequestID).ApprovedToken; got != "" {
		t.Errorf("approved_token = %q after the token was collected, want it cleared", got)
	}

	second := poll(t, reg, res.RequestID)
	if second.Status != store.RequestApproved {
		t.Errorf("second poll status = %q, want %q", second.Status, store.RequestApproved)
	}
	if second.Token != "" {
		t.Errorf("second poll returned the token again: %q", second.Token)
	}
	if second.MonClientID != approved.MonClientID {
		t.Errorf("second poll monClientId = %q, want %q", second.MonClientID, approved.MonClientID)
	}
}

func TestPollOfAnApprovedRequestSurvivesTheDeadline(t *testing.T) {
	reg, _, fake := newTestRegistry(t)
	res := submit(t, reg, "203.0.113.5", "7K3F9Q")
	approve(t, reg, res.RequestID, ApproveInput{Name: "ams 1"})

	// The administrator approved at the last second and the box polls after
	// the five minutes are up: it must still receive what it was granted.
	fake.Advance(RequestTTL + time.Minute)
	got := poll(t, reg, res.RequestID)
	if got.Status != store.RequestApproved || got.Token == "" {
		t.Fatalf("poll after the deadline = %+v, want an approved request with its token", got)
	}
}

func TestPollOfARejectedRequestSaysRejected(t *testing.T) {
	reg, _, _ := newTestRegistry(t)
	res := submit(t, reg, "203.0.113.5", "7K3F9Q")

	if err := reg.Reject(context.Background(), res.RequestID); err != nil {
		t.Fatalf("Reject: %v", err)
	}
	got := poll(t, reg, res.RequestID)
	if got.Status != store.RequestRejected {
		t.Fatalf("status = %q, want %q", got.Status, store.RequestRejected)
	}
	if got.Token != "" || got.MonClientID != "" {
		t.Errorf("a rejected request carried %+v, want nothing but the status", got)
	}
}

// TestRegistrationThroughTheHTTPEndpoints walks a mon-client's registration
// the way it really happens, over the two /v1 routes, so that the service and
// the handlers are proven to fit: the shapes of mon-protocol.md §2, the
// Retry-After the real rate-limit error produces, and the one-shot token.
func TestRegistrationThroughTheHTTPEndpoints(t *testing.T) {
	reg, _, fake := newTestRegistry(t)
	srv := api.New(reg, fake, slog.New(slog.DiscardHandler))
	api.RegisterRegistrationRoutes(srv, reg)
	mux := srv.Handler()

	do := func(req *http.Request) *httptest.ResponseRecorder {
		t.Helper()
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}
	post := func() *httptest.ResponseRecorder {
		t.Helper()
		body := `{"pairingCode":"7K3F9Q","hostname":"vps-ams-1","version":"0.1.0","publicIp":"203.0.113.9"}`
		req := httptest.NewRequest(http.MethodPost, "/v1/register", strings.NewReader(body))
		req.RemoteAddr = "203.0.113.5:54321"
		return do(req)
	}

	rec := post()
	if rec.Code != http.StatusAccepted {
		t.Fatalf("POST /v1/register = %d, want 202: %s", rec.Code, rec.Body)
	}
	var accepted struct {
		RequestID string `json:"requestId"`
		PollAfter int64  `json:"pollAfter"`
		ExpiresAt int64  `json:"expiresAt"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &accepted); err != nil {
		t.Fatalf("decode %q: %v", rec.Body, err)
	}
	if accepted.RequestID == "" || accepted.PollAfter != 10_000 {
		t.Fatalf("answer = %+v, want a requestId and a 10s poll interval", accepted)
	}

	// The same box straight away: refused with a Retry-After the mon-client
	// can act on.
	rec = post()
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second POST = %d, want 429", rec.Code)
	}
	after, err := strconv.Atoi(rec.Header().Get("Retry-After"))
	if err != nil || after < 1 || after > 60 {
		t.Fatalf("Retry-After = %q (%v), want a second count inside the minute", rec.Header().Get("Retry-After"), err)
	}

	pollHTTP := func() *httptest.ResponseRecorder {
		t.Helper()
		return do(httptest.NewRequest(http.MethodGet, "/v1/register/"+accepted.RequestID, nil))
	}
	rec = pollHTTP()
	if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != `{"status":"pending"}` {
		t.Fatalf("poll = %d %s, want 200 {\"status\":\"pending\"}", rec.Code, rec.Body)
	}

	// An unknown id gives nothing away.
	rec = do(httptest.NewRequest(http.MethodGet, "/v1/register/"+accepted.RequestID+"x", nil))
	if rec.Code != http.StatusNotFound || rec.Body.Len() != 0 {
		t.Fatalf("poll of an unknown id = %d %q, want a bare 404", rec.Code, rec.Body)
	}

	approve(t, reg, accepted.RequestID, ApproveInput{Name: "AMS 1", Region: "eu-west"})
	rec = pollHTTP()
	var approved struct {
		Status      string `json:"status"`
		MonClientID string `json:"monClientId"`
		Token       string `json:"token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &approved); err != nil {
		t.Fatalf("decode %q: %v", rec.Body, err)
	}
	if approved.Status != "approved" || approved.MonClientID != "ams-1" || approved.Token == "" {
		t.Fatalf("poll = %+v, want an approved request with its token", approved)
	}
	if strings.Contains(pollHTTP().Body.String(), approved.Token) {
		t.Error("the second poll handed the token out again")
	}

	// And the token it collected authenticates the box from then on.
	id, err := reg.AuthenticateClient(context.Background(), approved.Token)
	if err != nil || id.MonClientID != "ams-1" {
		t.Fatalf("AuthenticateClient = %+v, %v, want ams-1", id, err)
	}

	// Five minutes on, a request nobody decided is gone.
	fake.Advance(RequestTTL + time.Second)
	rec = post()
	if rec.Code != http.StatusAccepted {
		t.Fatalf("POST after the minute = %d, want 202: %s", rec.Code, rec.Body)
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &accepted); err != nil {
		t.Fatalf("decode %q: %v", rec.Body, err)
	}
	fake.Advance(RequestTTL + time.Second)
	rec = pollHTTP()
	if rec.Code != http.StatusGone {
		t.Fatalf("poll of an expired request = %d, want 410: %s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), `"request_expired"`) {
		t.Errorf("body = %s, want the request_expired code", rec.Body)
	}
}
