package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/SBKubric/3ax-ui-monitoring/internal/registry"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
)

// stubConfigs is a scriptable stand-in for *registry.ConfigBuilder: the
// handler's whole job is mapping its three outcomes onto status codes.
type stubConfigs struct {
	doc  *registry.ConfigDoc
	err  error
	seen []string
}

func (s *stubConfigs) Current(_ context.Context, monClientID string) (*registry.ConfigDoc, error) {
	s.seen = append(s.seen, monClientID)
	return s.doc, s.err
}

// newConfigTestServer mounts GET /v1/config exactly as internal/app does.
func newConfigTestServer(auth stubAuthenticator, cfgs *stubConfigs) *Server {
	s := New()
	ConfigRoutes(s.V1, auth, cfgs)
	return s
}

func getConfig(s *Server, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/v1/config", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	s.Engine.ServeHTTP(rec, req)
	return rec
}

// TestConfig_ServesTheAuthenticatedClientsDocument checks the happy path of
// protocol §4.2, including that the id asked for comes from the token and
// that the body is the document verbatim.
func TestConfig_ServesTheAuthenticatedClientsDocument(t *testing.T) {
	doc := &registry.ConfigDoc{
		ConfigRevision: "3a91c0de77b1f2e4",
		MonClientID:    "ams-1",
		ProbeURL:       "https://203.0.113.10:443/v1/probe",
		Probe:          registry.ProbeParams{IntervalMs: 60000, BudgetMs: 20000},
		Targets: []registry.ConfigTarget{
			{InboundKind: "xray", InboundID: 12, Path: "proxy", Protocol: "vless", Link: "vless://probe"},
		},
	}
	cfgs := &stubConfigs{doc: doc}
	s := newConfigTestServer(stubAuthenticator{client: &store.MonClient{Id: "ams-1"}}, cfgs)

	rec := getConfig(s, "tok")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	var got registry.ConfigDoc
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode body: %v (%s)", err, rec.Body.String())
	}
	if got.ConfigRevision != doc.ConfigRevision || got.MonClientID != "ams-1" || len(got.Targets) != 1 {
		t.Fatalf("body = %+v, want the stub document", got)
	}
	if got.Targets[0].Link != "vless://probe" || got.Probe.IntervalMs != 60000 {
		t.Fatalf("body target/probe = %+v / %+v, want them verbatim", got.Targets[0], got.Probe)
	}
	if len(cfgs.seen) != 1 || cfgs.seen[0] != "ams-1" {
		t.Fatalf("Current called with %v, want the authenticated id once", cfgs.seen)
	}
}

// TestConfig_NoConfigYetIs503 is spec §5's cold-start case: mon-server has
// never read material from the panel, so there is nothing to serve and the
// mon-client should come back.
func TestConfig_NoConfigYetIs503(t *testing.T) {
	s := newConfigTestServer(
		stubAuthenticator{client: &store.MonClient{Id: "ams-1"}},
		&stubConfigs{err: registry.ErrNoConfig},
	)

	rec := getConfig(s, "tok")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503, body=%s", rec.Code, rec.Body.String())
	}
	var body struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v (%s)", err, rec.Body.String())
	}
	if body.Error != "config_not_ready" {
		t.Fatalf("error = %q, want config_not_ready", body.Error)
	}
}

// TestConfig_InternalErrorIsNotLeaked checks a database failure becomes a
// bare 500: the driver's own message never reaches a mon-client.
func TestConfig_InternalErrorIsNotLeaked(t *testing.T) {
	s := newConfigTestServer(
		stubAuthenticator{client: &store.MonClient{Id: "ams-1"}},
		&stubConfigs{err: errors.New("database is locked: /var/lib/mon-server/mon.db")},
	)

	rec := getConfig(s, "tok")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500, body=%s", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); strings.Contains(body, "mon.db") {
		t.Fatalf("body leaks internal detail: %s", body)
	}
}

// TestConfig_RequiresClientToken checks the route really runs the middleware
// (protocol §3) — an unauthenticated fetch must never reach the builder.
func TestConfig_RequiresClientToken(t *testing.T) {
	cases := []struct {
		name  string
		auth  stubAuthenticator
		token string
		want  int
	}{
		{name: "no header", auth: stubAuthenticator{err: registry.ErrTokenRevoked}, want: http.StatusUnauthorized},
		{name: "revoked", auth: stubAuthenticator{err: registry.ErrTokenRevoked}, token: "tok", want: http.StatusUnauthorized},
		{name: "disabled", auth: stubAuthenticator{err: registry.ErrDisabled}, token: "tok", want: http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfgs := &stubConfigs{doc: &registry.ConfigDoc{}}
			s := newConfigTestServer(tc.auth, cfgs)
			rec := getConfig(s, tc.token)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d, body=%s", rec.Code, tc.want, rec.Body.String())
			}
			if len(cfgs.seen) != 0 {
				t.Fatalf("Current was called %v times for an unauthenticated request", cfgs.seen)
			}
		})
	}
}
