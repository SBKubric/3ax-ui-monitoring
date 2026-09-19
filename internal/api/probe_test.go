package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
	"github.com/SBKubric/3ax-ui-monitoring/internal/registry"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
)

// stubTargetKeys is a scriptable stand-in for *registry.ConfigBuilder's
// TargetKeys, so this package's tests can drive "known" vs. "unknown"
// target without building a real config document.
type stubTargetKeys struct {
	keys []registry.TargetKey
	err  error
}

func (s stubTargetKeys) TargetKeys(context.Context, string) ([]registry.TargetKey, error) {
	return s.keys, s.err
}

// newProbeTestServer mounts GET /v1/probe exactly as internal/app does,
// against a real temp-file store so tests can assert on probe_seen and
// targets rows.
func newProbeTestServer(t *testing.T, auth stubAuthenticator, keys stubTargetKeys) (*Server, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	st.Clock = clock.NewFake(time.UnixMilli(1_700_000_000_000).UTC())

	s := New()
	ProbeRoutes(s.V1, auth, keys, st)
	return s, st
}

func getProbe(s *Server, token, target, nonce string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/v1/probe?target="+target+"&n="+nonce, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.RemoteAddr = "198.51.100.42:12345"
	rec := httptest.NewRecorder()
	s.Engine.ServeHTTP(rec, req)
	return rec
}

// TestProbe_EchoesNonceAndSourceIP checks spec §7.5 / protocol §5.2's happy
// path: a known target answers 200 with the nonce echoed back verbatim and
// the request's own source IP as egressIp (the whole reason a probe travels
// through the tunnel is that this IP is the tunnel's egress, not
// mon-client's).
func TestProbe_EchoesNonceAndSourceIP(t *testing.T) {
	mc := &store.MonClient{Id: "ams-1"}
	keys := stubTargetKeys{keys: []registry.TargetKey{{InboundKind: "xray", InboundID: 12, Path: "proxy"}}}
	s, st := newProbeTestServer(t, stubAuthenticator{client: mc}, keys)

	rec := getProbe(s, "tok", "xray:12:proxy", "abc123")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}

	var body struct {
		Nonce    string `json:"nonce"`
		EgressIp string `json:"egressIp"`
		ServerTs int64  `json:"serverTs"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v (%s)", err, rec.Body.String())
	}
	if body.Nonce != "abc123" {
		t.Fatalf("nonce = %q, want echoed abc123", body.Nonce)
	}
	if body.EgressIp != "198.51.100.42" {
		t.Fatalf("egressIp = %q, want the request's source IP", body.EgressIp)
	}
	if body.ServerTs != clock.Ms(st.Clock.Now()) {
		t.Fatalf("serverTs = %d, want %d", body.ServerTs, clock.Ms(st.Clock.Now()))
	}

	var rows []store.ProbeSeen
	if err := st.DB.Find(&rows).Error; err != nil {
		t.Fatalf("read probe_seen: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("probe_seen rows = %d, want 1", len(rows))
	}
	if rows[0].UnknownTarget {
		t.Fatalf("row.UnknownTarget = true, want false for a known target")
	}
	if rows[0].MonClientId != "ams-1" || rows[0].InboundKind != "xray" || rows[0].InboundId != 12 || rows[0].Path != "proxy" {
		t.Fatalf("probe_seen row = %+v, want the parsed target", rows[0])
	}
	if rows[0].EgressIp != "198.51.100.42" {
		t.Fatalf("probe_seen egressIp = %q, want the source IP", rows[0].EgressIp)
	}
}

// TestProbe_RequiresClientToken checks the route runs RequireClientToken
// (protocol §3): an unauthenticated probe never reaches the handler at all,
// let alone gets logged.
func TestProbe_RequiresClientToken(t *testing.T) {
	s, st := newProbeTestServer(t, stubAuthenticator{err: registry.ErrTokenRevoked}, stubTargetKeys{})

	rec := getProbe(s, "", "xray:12:proxy", "n")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401, body=%s", rec.Code, rec.Body.String())
	}

	var rows []store.ProbeSeen
	if err := st.DB.Find(&rows).Error; err != nil {
		t.Fatalf("read probe_seen: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("probe_seen rows = %d, want 0 for an unauthenticated request", len(rows))
	}
}

// TestProbe_UnknownTargetIsStill200 is spec §7.5's diagnostic case: a
// target this mon-client's config does not name still gets a 200 (the
// probe result is not this mon-client's fault to explain), but the
// probe_seen row is flagged.
func TestProbe_UnknownTargetIsStill200(t *testing.T) {
	mc := &store.MonClient{Id: "ams-1"}
	keys := stubTargetKeys{keys: []registry.TargetKey{{InboundKind: "xray", InboundID: 12, Path: "proxy"}}}
	s, st := newProbeTestServer(t, stubAuthenticator{client: mc}, keys)

	rec := getProbe(s, "tok", "xray:99:direct", "n1")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}

	var rows []store.ProbeSeen
	if err := st.DB.Find(&rows).Error; err != nil {
		t.Fatalf("read probe_seen: %v", err)
	}
	if len(rows) != 1 || !rows[0].UnknownTarget {
		t.Fatalf("probe_seen rows = %+v, want one row with UnknownTarget = true", rows)
	}
}

// TestProbe_TargetKeysErrorStillAnswers200 checks that a config-builder
// failure (a database hiccup, say) never turns into a failed probe: the
// mon-client's own success does not depend on mon-server's diagnostics
// bookkeeping.
func TestProbe_TargetKeysErrorStillAnswers200(t *testing.T) {
	mc := &store.MonClient{Id: "ams-1"}
	keys := stubTargetKeys{err: errTargetKeysBoom}
	s, st := newProbeTestServer(t, stubAuthenticator{client: mc}, keys)

	rec := getProbe(s, "tok", "xray:12:proxy", "n1")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}

	var rows []store.ProbeSeen
	if err := st.DB.Find(&rows).Error; err != nil {
		t.Fatalf("read probe_seen: %v", err)
	}
	if len(rows) != 1 || !rows[0].UnknownTarget {
		t.Fatalf("probe_seen rows = %+v, want one row, conservatively flagged unknown", rows)
	}
}

// TestProbe_BadRequests checks spec §7.5's malformed-input cases all become
// 400 bad_request without ever touching probe_seen.
func TestProbe_BadRequests(t *testing.T) {
	cases := []struct {
		name   string
		target string
		nonce  string
	}{
		{"missing target", "", "n"},
		{"malformed target: too few parts", "xray:12", "n"},
		{"malformed target: bad kind", "vmess:12:proxy", "n"},
		{"malformed target: bad path", "xray:12:sideways", "n"},
		{"malformed target: non-numeric inbound id", "xray:abc:proxy", "n"},
		{"malformed target: negative inbound id", "xray:-1:proxy", "n"},
		{"missing nonce", "xray:12:proxy", ""},
		{"oversized nonce", "xray:12:proxy", strings.Repeat("a", maxNonceLen+1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mc := &store.MonClient{Id: "ams-1"}
			s, st := newProbeTestServer(t, stubAuthenticator{client: mc}, stubTargetKeys{})

			rec := getProbe(s, "tok", tc.target, tc.nonce)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400, body=%s", rec.Code, rec.Body.String())
			}

			var rows []store.ProbeSeen
			if err := st.DB.Find(&rows).Error; err != nil {
				t.Fatalf("read probe_seen: %v", err)
			}
			if len(rows) != 0 {
				t.Fatalf("probe_seen rows = %d, want 0 for a rejected request", len(rows))
			}
		})
	}
}

// TestProbe_NeverTouchesTargets is the issue's explicit requirement: a
// probe is diagnostics, never state (spec §7.5: "состояние по этим запросам
// не считается") — the targets table must be byte-for-byte unchanged by a
// probe, known or unknown.
func TestProbe_NeverTouchesTargets(t *testing.T) {
	mc := &store.MonClient{Id: "ams-1"}
	keys := stubTargetKeys{keys: []registry.TargetKey{{InboundKind: "xray", InboundID: 12, Path: "proxy"}}}
	s, st := newProbeTestServer(t, stubAuthenticator{client: mc}, keys)

	seed := store.Target{MonClientId: "ams-1", InboundKind: "xray", InboundId: 12, Path: "proxy", State: store.TargetUnknown}
	if err := st.DB.Create(&seed).Error; err != nil {
		t.Fatalf("seed target: %v", err)
	}
	var before []store.Target
	if err := st.DB.Find(&before).Error; err != nil {
		t.Fatalf("read targets before: %v", err)
	}

	// One known-target probe and one unknown-target probe: neither should
	// touch targets.
	if rec := getProbe(s, "tok", "xray:12:proxy", "n1"); rec.Code != http.StatusOK {
		t.Fatalf("known-target probe status = %d, want 200", rec.Code)
	}
	if rec := getProbe(s, "tok", "xray:77:direct", "n2"); rec.Code != http.StatusOK {
		t.Fatalf("unknown-target probe status = %d, want 200", rec.Code)
	}

	var after []store.Target
	if err := st.DB.Find(&after).Error; err != nil {
		t.Fatalf("read targets after: %v", err)
	}
	if len(after) != len(before) {
		t.Fatalf("targets rows = %d, want unchanged %d", len(after), len(before))
	}
	if after[0] != before[0] {
		t.Fatalf("targets row changed: before=%+v after=%+v", before[0], after[0])
	}
}

// errTargetKeysBoom stands in for a database failure inside TargetKeys.
var errTargetKeysBoom = &boomError{"boom"}

type boomError struct{ s string }

func (e *boomError) Error() string { return e.s }
