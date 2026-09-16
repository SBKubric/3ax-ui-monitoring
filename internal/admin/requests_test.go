package admin

import (
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
)

// samplePending is the pending request the Requests tests work with.
func samplePending() PendingRequest {
	return PendingRequest{
		RequestID:   "req-1",
		PairingCode: "7K3F9Q",
		Hostname:    "vps-ams-2",
		Version:     "0.1.0",
		PublicIP:    "203.0.113.5",
		RemoteIP:    "203.0.113.5",
		CreatedAt:   clock.MS(testTime) - 80_000,
		ExpiresAt:   clock.MS(testTime) + 220_000,
		Attempt:     2,
		Matches:     []ReplacementHint{{MonClientID: "msk-1", Name: "Moscow #1", Reason: MatchHostname}},
	}
}

// TestRequestsListCarriesTheHints: the page gets the requests, the rate limits
// and the registry the replacement picker needs.
func TestRequestsListCarriesTheHints(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.registry.pending = []PendingRequest{samplePending()}
	h.registry.clients = []Client{{ID: "msk-1", Name: "Moscow #1", Region: "RU", Paths: []string{"proxy"}, State: "ONLINE"}}
	cookie := h.signIn()

	rec := h.get("/admin/api/requests", cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	var payload requestsPayload
	decodeObj(t, rec, &payload)

	if payload.Pending != 1 {
		t.Errorf("pending = %d, want 1", payload.Pending)
	}
	if payload.ServerTime != clock.MS(testTime) {
		t.Errorf("serverTime = %d, want %d", payload.ServerTime, clock.MS(testTime))
	}
	if payload.RateLimits != DefaultRateLimits() {
		t.Errorf("rateLimits = %+v, want %+v", payload.RateLimits, DefaultRateLimits())
	}
	if len(payload.Requests) != 1 {
		t.Fatalf("got %d requests, want 1", len(payload.Requests))
	}
	got := payload.Requests[0]
	if got.PairingCode != "7K3F9Q" || got.Attempt != 2 {
		t.Errorf("request = %+v, want the pairing code and the attempt number", got)
	}
	if len(got.Matches) != 1 || got.Matches[0].MonClientID != "msk-1" || got.Matches[0].Reason != MatchHostname {
		t.Errorf("matches = %+v, want the hostname hint for msk-1", got.Matches)
	}
	if len(payload.Clients) != 1 || payload.Clients[0].ID != "msk-1" {
		t.Errorf("clients = %+v, want the registry for the replacement picker", payload.Clients)
	}
}

// TestRequestsListIsEmptyNotNull keeps the page from having to guard.
func TestRequestsListIsEmptyNotNull(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	cookie := h.signIn()

	rec := h.get("/admin/api/requests", cookie)
	var payload requestsPayload
	decodeObj(t, rec, &payload)
	if payload.Requests == nil || payload.Clients == nil {
		t.Fatalf("payload = %+v, want empty lists rather than null", payload)
	}
}

// TestApproveReachesTheRegistry: what the modal produced arrives unchanged.
func TestApproveReachesTheRegistry(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.registry.pending = []PendingRequest{samplePending()}
	h.registry.approved = Client{ID: "ams-2", Name: "Amsterdam #2", Region: "NL", Paths: []string{"proxy", "direct"}}
	cookie := h.signIn()

	body := map[string]any{
		"mode":   "new",
		"name":   "  Amsterdam #2  ",
		"region": " NL ",
		"paths":  []string{"direct", "proxy"},
	}
	rec := h.post("/admin/api/requests/req-1/approve", body, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	if len(h.registry.approvals) != 1 {
		t.Fatalf("got %d approvals, want 1", len(h.registry.approvals))
	}
	got := h.registry.approvals[0]
	want := Approval{
		RequestID: "req-1",
		Replace:   false,
		Name:      "Amsterdam #2",
		Region:    "NL",
		// Canonical order, so an equal set always builds the same document.
		Paths: []string{"proxy", "direct"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("approval = %+v, want %+v", got, want)
	}
	var client Client
	decodeObj(t, rec, &client)
	if client.ID != "ams-2" {
		t.Errorf("returned client = %+v, want the registry's row", client)
	}
}

// TestApproveAsReplacementReachesTheRegistry covers the second mode of §9.2.
func TestApproveAsReplacementReachesTheRegistry(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.registry.pending = []PendingRequest{samplePending()}
	h.registry.clients = []Client{{ID: "msk-1", Name: "Moscow #1", Region: "RU", Paths: []string{"proxy"}}}
	h.registry.approved = Client{ID: "msk-1", Name: "Moscow #1", Region: "RU", Paths: []string{"proxy"}}
	cookie := h.signIn()

	body := map[string]any{
		"mode":        "replace",
		"monClientId": "msk-1",
		"name":        "Moscow #1",
		"region":      "RU",
		"paths":       []string{"proxy"},
	}
	rec := h.post("/admin/api/requests/req-1/approve", body, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	if len(h.registry.approvals) != 1 {
		t.Fatalf("got %d approvals, want 1", len(h.registry.approvals))
	}
	got := h.registry.approvals[0]
	if !got.Replace || got.MonClientID != "msk-1" {
		t.Errorf("approval = %+v, want a replacement of msk-1", got)
	}
	if !reflect.DeepEqual(got.Paths, []string{"proxy"}) {
		t.Errorf("paths = %v, want [proxy]", got.Paths)
	}
}

// TestApproveRefusesBadInput: everything the registry must never see is
// refused before it is called.
func TestApproveRefusesBadInput(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		body map[string]any
		want string
	}{
		{
			name: "empty name",
			body: map[string]any{"mode": "new", "name": "   ", "paths": []string{"proxy"}},
			want: "the name is required",
		},
		{
			name: "unknown path",
			body: map[string]any{"mode": "new", "name": "Amsterdam", "paths": []string{"proxy", "tunnel"}},
			want: "unknown path",
		},
		{
			name: "no path at all",
			body: map[string]any{"mode": "new", "name": "Amsterdam", "paths": []string{}},
			want: "at least one path",
		},
		{
			name: "unknown mode",
			body: map[string]any{"mode": "sideways", "name": "Amsterdam", "paths": []string{"proxy"}},
			want: "unknown approval mode",
		},
		{
			name: "replacement without a record",
			body: map[string]any{"mode": "replace", "paths": []string{"proxy"}},
			want: "choose the mon-client",
		},
		{
			name: "replacement of an impossible id",
			body: map[string]any{"mode": "replace", "monClientId": "not a slug!", "paths": []string{"proxy"}},
			want: "is not a mon-client id",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			cookie := h.signIn()

			rec := h.post("/admin/api/requests/req-1/approve", c.body, cookie)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (%s)", rec.Code, rec.Body.String())
			}
			env := decode(t, rec)
			if env.Success {
				t.Error("the envelope reports success on invalid input")
			}
			if !strings.Contains(env.Msg, c.want) {
				t.Errorf("msg = %q, want it to mention %q", env.Msg, c.want)
			}
			if len(h.registry.approvals) != 0 {
				t.Errorf("the registry was called with %+v", h.registry.approvals)
			}
		})
	}
}

// TestApproveRefusesAnOverlongName keeps the id derivation sane.
func TestApproveRefusesAnOverlongName(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	cookie := h.signIn()

	long := make([]byte, maxNameLen+1)
	for i := range long {
		long[i] = 'a'
	}
	body := map[string]any{"mode": "new", "name": string(long), "paths": []string{"proxy"}}
	if rec := h.post("/admin/api/requests/req-1/approve", body, cookie); rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if len(h.registry.approvals) != 0 {
		t.Error("the registry was called with an overlong name")
	}
}

// TestRejectReachesTheRegistry.
func TestRejectReachesTheRegistry(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	cookie := h.signIn()

	rec := h.post("/admin/api/requests/req-1/reject", nil, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	if !reflect.DeepEqual(h.registry.rejects, []string{"req-1"}) {
		t.Errorf("rejects = %v, want [req-1]", h.registry.rejects)
	}
}

// TestRegistryErrorsBecomeStatuses maps the sentinels of ports.go.
func TestRegistryErrorsBecomeStatuses(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"not found", ErrNotFound, http.StatusNotFound},
		{"conflict", ErrConflict, http.StatusConflict},
		{"invalid", ErrInvalid, http.StatusBadRequest},
		{"anything else", errFake, http.StatusInternalServerError},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			cookie := h.signIn()
			h.registry.err = c.err

			rec := h.post("/admin/api/requests/req-1/reject", nil, cookie)
			if rec.Code != c.want {
				t.Fatalf("status = %d, want %d (%s)", rec.Code, c.want, rec.Body.String())
			}
			if env := decode(t, rec); env.Success {
				t.Error("the envelope reports success on a failure")
			}
		})
	}
}

// TestCleanPaths covers the checkbox validation directly.
func TestCleanPaths(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		in      []string
		want    []string
		wantErr bool
	}{
		{name: "both, out of order", in: []string{"direct", "proxy"}, want: []string{"proxy", "direct"}},
		{name: "duplicates collapse", in: []string{"proxy", "proxy"}, want: []string{"proxy"}},
		{name: "spaces are trimmed", in: []string{" direct "}, want: []string{"direct"}},
		{name: "empty", in: nil, wantErr: true},
		{name: "unknown", in: []string{"tunnel"}, wantErr: true},
		{name: "empty string", in: []string{""}, wantErr: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			got, err := cleanPaths(c.in)
			if c.wantErr {
				if err == nil {
					t.Fatalf("cleanPaths(%v) = %v, want an error", c.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("cleanPaths(%v): %v", c.in, err)
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("cleanPaths(%v) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}
