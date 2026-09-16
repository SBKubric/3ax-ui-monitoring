package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
)

const (
	probeTestClientID = "ams-1"
	probeTestToken    = "client-token-of-ams-1"
	// probeTestRemote is the address the request arrives from: through a
	// tunnel this is the egress of that tunnel, not the mon-client's own IP.
	probeTestRemote   = "198.51.100.77:41234"
	probeTestEgressIP = "198.51.100.77"
	// probeTestSpoofedIP is what a forwarding header claims; egressIp must
	// never report it.
	probeTestSpoofedIP = "203.0.113.9"
)

// probeTestTime is the instant the fake clock of these tests stands at.
var probeTestTime = time.Date(2025, 9, 13, 10, 0, 0, 0, time.UTC)

// probeTestDocument is the configuration document served to probeTestClientID
// (mon-protocol.md §4.2). Its targets array decides target membership: the
// mon-client has xray:12:proxy, xray:12:direct and awg:0:proxy.
const probeTestDocument = `{
  "configRevision": "3a91c0de77b1f2e4",
  "monClientId": "ams-1",
  "probeUrl": "https://203.0.113.10:443/v1/probe",
  "probe": {"intervalMs": 60000, "budgetMs": 20000},
  "targets": [
    {"inboundKind": "xray", "inboundId": 12, "path": "proxy",  "protocol": "vless", "link": "vless://probe@front.example.net:443#probe-12"},
    {"inboundKind": "xray", "inboundId": 12, "path": "direct", "protocol": "vless", "link": "vless://probe@203.0.113.10:443#probe-12"},
    {"inboundKind": "awg",  "inboundId": 0,  "path": "proxy",  "protocol": "awg",   "conf": "[Interface]\n[Peer]\n"}
  ]
}`

// probeFakeAuth is an Authenticator that knows one token, so the handler can
// be driven through every outcome of mon-protocol.md §3.
type probeFakeAuth struct {
	token    string
	clientID string
	disabled bool
}

// AuthenticateClient implements Authenticator.
func (a probeFakeAuth) AuthenticateClient(_ context.Context, token string) (Identity, error) {
	if token != a.token {
		return Identity{}, ErrTokenRevoked
	}
	if a.disabled {
		return Identity{}, ErrClientDisabled
	}
	return Identity{MonClientID: a.clientID}, nil
}

// probeFakeService is a ProbeService whose answers the test dictates, for the
// failure paths a real store will not produce on demand.
type probeFakeService struct {
	mu        sync.Mutex
	known     bool
	lookupErr error
	writeErr  error
	rows      []store.ProbeSeen
}

// HasProbeTarget implements ProbeTargets.
func (f *probeFakeService) HasProbeTarget(context.Context, string, ProbeTarget) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.known, f.lookupErr
}

// RecordProbeSeen implements ProbeService.
func (f *probeFakeService) RecordProbeSeen(_ context.Context, seen store.ProbeSeen) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.writeErr != nil {
		return f.writeErr
	}
	f.rows = append(f.rows, seen)
	return nil
}

// recorded returns the rows the fake accepted.
func (f *probeFakeService) recorded() []store.ProbeSeen {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]store.ProbeSeen(nil), f.rows...)
}

// probeTestStore opens a store on a fresh file, seeded with the mon-client,
// the configuration document it is served and two targets rows whose state no
// probe may ever touch.
func probeTestStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "mon-server.db"), nil, store.WithClock(clock.NewFake(probeTestTime)))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() {
		if err := st.Close(); err != nil {
			t.Errorf("close store: %v", err)
		}
	})
	paths, err := store.EncodePaths(store.DefaultPaths())
	if err != nil {
		t.Fatalf("encode paths: %v", err)
	}
	seed := []any{
		&store.MonClient{
			ID: probeTestClientID, Name: "ams-1", Region: "ams", Paths: paths,
			TokenHash: store.HashToken(probeTestToken), Enabled: true,
			State: store.ClientStateOnline, LastHeartbeat: clock.MS(probeTestTime),
		},
		&store.ClientConfig{
			MonClientID: probeTestClientID, Revision: "3a91c0de77b1f2e4",
			Document: probeTestDocument, BuiltAt: clock.MS(probeTestTime),
		},
		&store.Target{
			MonClientID: probeTestClientID, InboundKind: store.InboundKindXray, InboundID: 12, Path: store.PathProxy,
			State: store.TargetUp, Since: clock.MS(probeTestTime), ConsecutiveOK: 2, LastResultAt: clock.MS(probeTestTime),
		},
		&store.Target{
			MonClientID: probeTestClientID, InboundKind: store.InboundKindXray, InboundID: 12, Path: store.PathDirect,
			State: store.TargetDown, Since: clock.MS(probeTestTime), Reason: "connect timeout", ConsecutiveFail: 3, LastResultAt: clock.MS(probeTestTime),
		},
	}
	for _, row := range seed {
		if err := st.DB().Create(row).Error; err != nil {
			t.Fatalf("seed %T: %v", row, err)
		}
	}
	return st
}

// probeTestServer wires GET /v1/probe onto svc behind a fake authenticator.
func probeTestServer(t *testing.T, svc ProbeService, disabled bool) *Server {
	t.Helper()
	auth := probeFakeAuth{token: probeTestToken, clientID: probeTestClientID, disabled: disabled}
	srv := New(auth, clock.NewFake(probeTestTime), slog.New(slog.DiscardHandler))
	RegisterProbeRoutes(srv, svc)
	return srv
}

// probeTestSetup is the common case: the endpoint on the default store-backed
// service, reading the seeded configuration document.
func probeTestSetup(t *testing.T) (*Server, *store.Store) {
	t.Helper()
	st := probeTestStore(t)
	return probeTestServer(t, NewProbeStore(st, nil), false), st
}

// probeTestRequest builds a probe request from query values. An empty token
// leaves the Authorization header off entirely.
func probeTestRequest(values url.Values, token string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/v1/probe?"+values.Encode(), nil)
	r.RemoteAddr = probeTestRemote
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	// Forwarding headers are always present in these tests: none of them may
	// reach egressIp.
	r.Header.Set("X-Forwarded-For", probeTestSpoofedIP)
	r.Header.Set("X-Real-IP", probeTestSpoofedIP)
	return r
}

// probeTestQuery is the query of a well-formed probe.
func probeTestQuery(target, nonce string) url.Values {
	return url.Values{"target": {target}, "n": {nonce}}
}

// probeTestDo runs one request against the handler.
func probeTestDo(srv *Server, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

// probeTestBody decodes a successful probe answer.
func probeTestBody(t *testing.T, rec *httptest.ResponseRecorder) probeResponse {
	t.Helper()
	var body probeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body %q: %v", rec.Body.String(), err)
	}
	return body
}

// probeTestErrorCode decodes the error envelope of mon-protocol.md §1.
func probeTestErrorCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var body ErrorBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode error body %q: %v", rec.Body.String(), err)
	}
	return body.Error
}

// probeTestSeenRows reads probe_seen in insertion order.
func probeTestSeenRows(t *testing.T, st *store.Store) []store.ProbeSeen {
	t.Helper()
	var rows []store.ProbeSeen
	if err := st.DB().Order("id").Find(&rows).Error; err != nil {
		t.Fatalf("read probe_seen: %v", err)
	}
	return rows
}

// probeTestTargetRows reads every targets row, the table this endpoint must
// leave alone.
func probeTestTargetRows(t *testing.T, st *store.Store) []store.Target {
	t.Helper()
	var rows []store.Target
	if err := st.DB().Order("id").Find(&rows).Error; err != nil {
		t.Fatalf("read targets: %v", err)
	}
	return rows
}

func TestProbeAnswersNonceEgressAndServerTime(t *testing.T) {
	srv, st := probeTestSetup(t)

	rec := probeTestDo(srv, probeTestRequest(probeTestQuery("xray:12:proxy", "9f8e7d6c"), probeTestToken))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (body %q)", rec.Code, http.StatusOK, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Errorf("Content-Type = %q", ct)
	}
	got := probeTestBody(t, rec)
	want := probeResponse{Nonce: "9f8e7d6c", EgressIP: probeTestEgressIP, ServerTS: clock.MS(probeTestTime)}
	if got != want {
		t.Errorf("body = %+v, want %+v", got, want)
	}

	rows := probeTestSeenRows(t, st)
	if len(rows) != 1 {
		t.Fatalf("probe_seen rows = %d, want 1", len(rows))
	}
	rows[0].ID = 0
	wantRow := store.ProbeSeen{
		MonClientID: probeTestClientID, InboundKind: store.InboundKindXray, InboundID: 12, Path: store.PathProxy,
		EgressIP: probeTestEgressIP, SeenAt: clock.MS(probeTestTime), UnknownTarget: false,
	}
	if rows[0] != wantRow {
		t.Errorf("probe_seen row = %+v, want %+v", rows[0], wantRow)
	}
}

func TestProbeEgressIPIsTheConnectionSource(t *testing.T) {
	srv, _ := probeTestSetup(t)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/v1/probe?target=xray:12:proxy&n=abc", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+probeTestToken)
	req.Header.Set("X-Forwarded-For", probeTestSpoofedIP)
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var body probeResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.EgressIP == probeTestSpoofedIP {
		t.Fatalf("egressIp = %q: a forwarding header must never decide it", body.EgressIP)
	}
	if ip := net.ParseIP(body.EgressIP); ip == nil || !ip.IsLoopback() {
		t.Errorf("egressIp = %q, want the loopback source address of the connection", body.EgressIP)
	}
}

func TestProbeRequiresClientToken(t *testing.T) {
	cases := []struct {
		name       string
		token      string
		disabled   bool
		wantStatus int
		wantError  string
	}{
		{name: "no token", token: "", wantStatus: http.StatusUnauthorized, wantError: ErrCodeTokenRevoked},
		{name: "unknown token", token: "not-a-known-token", wantStatus: http.StatusUnauthorized, wantError: ErrCodeTokenRevoked},
		{name: "disabled mon-client", token: probeTestToken, disabled: true, wantStatus: http.StatusForbidden, wantError: ErrCodeDisabled},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := probeTestStore(t)
			srv := probeTestServer(t, NewProbeStore(st, nil), tc.disabled)

			rec := probeTestDo(srv, probeTestRequest(probeTestQuery("xray:12:proxy", "nonce"), tc.token))

			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d (body %q)", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if code := probeTestErrorCode(t, rec); code != tc.wantError {
				t.Errorf("error = %q, want %q", code, tc.wantError)
			}
			if rows := probeTestSeenRows(t, st); len(rows) != 0 {
				t.Errorf("probe_seen rows = %d, want none for a rejected caller", len(rows))
			}
		})
	}
}

func TestProbeTargetParameter(t *testing.T) {
	cases := []struct {
		name string
		// target is the raw target= value.
		target string
		// wantStatus is 200 for a parseable target, whether or not the
		// mon-client has it, and 400 for a malformed one.
		wantStatus int
		// wantRow is the probe_seen row a 200 must write, without the fields
		// every row shares.
		wantRow store.ProbeSeen
	}{
		{
			name: "target of this mon-client", target: "xray:12:proxy", wantStatus: http.StatusOK,
			wantRow: store.ProbeSeen{InboundKind: store.InboundKindXray, InboundID: 12, Path: store.PathProxy},
		},
		{
			name: "direct path of this mon-client", target: "xray:12:direct", wantStatus: http.StatusOK,
			wantRow: store.ProbeSeen{InboundKind: store.InboundKindXray, InboundID: 12, Path: store.PathDirect},
		},
		{
			name: "awg inbound id zero is a real id", target: "awg:0:proxy", wantStatus: http.StatusOK,
			wantRow: store.ProbeSeen{InboundKind: store.InboundKindAWG, InboundID: 0, Path: store.PathProxy},
		},
		{
			name: "awg inbound id zero this mon-client does not have", target: "awg:0:direct", wantStatus: http.StatusOK,
			wantRow: store.ProbeSeen{InboundKind: store.InboundKindAWG, InboundID: 0, Path: store.PathDirect, UnknownTarget: true},
		},
		{
			name: "inbound this mon-client does not have", target: "xray:99:proxy", wantStatus: http.StatusOK,
			wantRow: store.ProbeSeen{InboundKind: store.InboundKindXray, InboundID: 99, Path: store.PathProxy, UnknownTarget: true},
		},
		{name: "empty target", target: "", wantStatus: http.StatusBadRequest},
		{name: "no colons", target: "xray12proxy", wantStatus: http.StatusBadRequest},
		{name: "one colon", target: "xray:12", wantStatus: http.StatusBadRequest},
		{name: "one colon too many", target: "xray:12:proxy:extra", wantStatus: http.StatusBadRequest},
		{name: "non numeric inbound id", target: "xray:abc:proxy", wantStatus: http.StatusBadRequest},
		{name: "negative inbound id", target: "xray:-1:proxy", wantStatus: http.StatusBadRequest},
		{name: "non canonical inbound id", target: "xray:012:proxy", wantStatus: http.StatusBadRequest},
		{name: "unknown path", target: "xray:12:tunnel", wantStatus: http.StatusBadRequest},
		{name: "empty path", target: "xray:12:", wantStatus: http.StatusBadRequest},
		{name: "empty kind", target: ":12:proxy", wantStatus: http.StatusBadRequest},
		{name: "unknown kind", target: "socks:12:proxy", wantStatus: http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, st := probeTestSetup(t)

			rec := probeTestDo(srv, probeTestRequest(probeTestQuery(tc.target, "nonce-1"), probeTestToken))

			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d (body %q)", rec.Code, tc.wantStatus, rec.Body.String())
			}
			rows := probeTestSeenRows(t, st)
			if tc.wantStatus != http.StatusOK {
				if code := probeTestErrorCode(t, rec); code != ErrCodeInvalidBody {
					t.Errorf("error = %q, want %q", code, ErrCodeInvalidBody)
				}
				if len(rows) != 0 {
					t.Errorf("probe_seen rows = %d, want none for a malformed target", len(rows))
				}
				return
			}
			if got := probeTestBody(t, rec); got.Nonce != "nonce-1" {
				t.Errorf("nonce = %q, want %q", got.Nonce, "nonce-1")
			}
			if len(rows) != 1 {
				t.Fatalf("probe_seen rows = %d, want 1", len(rows))
			}
			want := tc.wantRow
			want.MonClientID = probeTestClientID
			want.EgressIP = probeTestEgressIP
			want.SeenAt = clock.MS(probeTestTime)
			rows[0].ID = 0
			if rows[0] != want {
				t.Errorf("probe_seen row = %+v, want %+v", rows[0], want)
			}
		})
	}
}

func TestProbeNonce(t *testing.T) {
	maxNonce := strings.Repeat("a", probeMaxNonceLen)
	cases := []struct {
		name       string
		values     url.Values
		wantStatus int
		wantNonce  string
	}{
		{name: "missing nonce", values: url.Values{"target": {"xray:12:proxy"}}, wantStatus: http.StatusBadRequest},
		{name: "empty nonce", values: probeTestQuery("xray:12:proxy", ""), wantStatus: http.StatusBadRequest},
		{name: "nonce at the cap", values: probeTestQuery("xray:12:proxy", maxNonce), wantStatus: http.StatusOK, wantNonce: maxNonce},
		{name: "nonce over the cap", values: probeTestQuery("xray:12:proxy", maxNonce+"a"), wantStatus: http.StatusBadRequest},
		{name: "nonce echoed verbatim", values: probeTestQuery("xray:12:proxy", "A z/+=%21-_.~"), wantStatus: http.StatusOK, wantNonce: "A z/+=%21-_.~"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, st := probeTestSetup(t)

			rec := probeTestDo(srv, probeTestRequest(tc.values, probeTestToken))

			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d (body %q)", rec.Code, tc.wantStatus, rec.Body.String())
			}
			rows := probeTestSeenRows(t, st)
			if tc.wantStatus != http.StatusOK {
				if code := probeTestErrorCode(t, rec); code != ErrCodeInvalidBody {
					t.Errorf("error = %q, want %q", code, ErrCodeInvalidBody)
				}
				if len(rows) != 0 {
					t.Errorf("probe_seen rows = %d, want none for a rejected nonce", len(rows))
				}
				return
			}
			if got := probeTestBody(t, rec); got.Nonce != tc.wantNonce {
				t.Errorf("nonce = %q, want %q", got.Nonce, tc.wantNonce)
			}
			if len(rows) != 1 {
				t.Errorf("probe_seen rows = %d, want 1", len(rows))
			}
		})
	}
}

func TestProbeLeavesTargetsUntouched(t *testing.T) {
	// The probe says nothing about a target's state: mon-server decides UP
	// and DOWN from the heartbeat, because the probe's destination is
	// mon-server itself (spec §7.5). This is the rule a later change is most
	// likely to break, so the table is compared row by row.
	srv, st := probeTestSetup(t)
	before := probeTestTargetRows(t, st)
	if len(before) == 0 {
		t.Fatal("no targets rows seeded: the assertion would be vacuous")
	}

	for _, target := range []string{"xray:12:proxy", "xray:12:direct", "xray:99:proxy"} {
		rec := probeTestDo(srv, probeTestRequest(probeTestQuery(target, "nonce"), probeTestToken))
		if rec.Code != http.StatusOK {
			t.Fatalf("probe %s: status = %d, want %d (body %q)", target, rec.Code, http.StatusOK, rec.Body.String())
		}
	}

	after := probeTestTargetRows(t, st)
	if !reflect.DeepEqual(before, after) {
		t.Errorf("targets changed:\nbefore %+v\nafter  %+v", before, after)
	}
}

func TestProbeSurvivesServiceFailures(t *testing.T) {
	cases := []struct {
		name string
		svc  *probeFakeService
		// wantRows is how many rows the service accepted.
		wantRows int
		// wantUnknown is the flag on the recorded row, if any.
		wantUnknown bool
	}{
		{
			name:     "probe_seen write fails",
			svc:      &probeFakeService{known: true, writeErr: errors.New("database is locked")},
			wantRows: 0,
		},
		{
			name:        "membership lookup fails",
			svc:         &probeFakeService{lookupErr: errors.New("database is locked")},
			wantRows:    1,
			wantUnknown: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := probeTestServer(t, tc.svc, false)

			rec := probeTestDo(srv, probeTestRequest(probeTestQuery("xray:12:proxy", "nonce-2"), probeTestToken))

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d: diagnostics must not fail the probe (body %q)", rec.Code, http.StatusOK, rec.Body.String())
			}
			got := probeTestBody(t, rec)
			want := probeResponse{Nonce: "nonce-2", EgressIP: probeTestEgressIP, ServerTS: clock.MS(probeTestTime)}
			if got != want {
				t.Errorf("body = %+v, want %+v", got, want)
			}
			rows := tc.svc.recorded()
			if len(rows) != tc.wantRows {
				t.Fatalf("recorded rows = %d, want %d", len(rows), tc.wantRows)
			}
			if len(rows) == 1 && rows[0].UnknownTarget != tc.wantUnknown {
				t.Errorf("unknown_target = %v, want %v: the flag needs positive evidence, not a failed lookup", rows[0].UnknownTarget, tc.wantUnknown)
			}
		})
	}
}

func TestProbeStoreUsesInjectedTargetLookup(t *testing.T) {
	// The wiring layer passes the internal/clientcfg builder instead of the
	// stored document; the store-backed service must defer to it.
	st := probeTestStore(t)
	lookup := &probeFakeService{known: false}
	srv := probeTestServer(t, NewProbeStore(st, lookup), false)

	// xray:12:proxy IS in the stored document, so a flagged row proves the
	// injected lookup decided it.
	rec := probeTestDo(srv, probeTestRequest(probeTestQuery("xray:12:proxy", "nonce-3"), probeTestToken))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (body %q)", rec.Code, http.StatusOK, rec.Body.String())
	}
	rows := probeTestSeenRows(t, st)
	if len(rows) != 1 {
		t.Fatalf("probe_seen rows = %d, want 1", len(rows))
	}
	if !rows[0].UnknownTarget {
		t.Error("unknown_target = false, want true: the injected lookup was not consulted")
	}
}

func TestProbeStoreWithoutConfigFlagsEveryTarget(t *testing.T) {
	// A mon-client whose configuration has not been built yet has no targets
	// at all; the probe is still answered.
	st := probeTestStore(t)
	if err := st.DB().Where("mon_client_id = ?", probeTestClientID).Delete(&store.ClientConfig{}).Error; err != nil {
		t.Fatalf("delete client config: %v", err)
	}
	srv := probeTestServer(t, NewProbeStore(st, nil), false)

	rec := probeTestDo(srv, probeTestRequest(probeTestQuery("xray:12:proxy", "nonce-4"), probeTestToken))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (body %q)", rec.Code, http.StatusOK, rec.Body.String())
	}
	rows := probeTestSeenRows(t, st)
	if len(rows) != 1 {
		t.Fatalf("probe_seen rows = %d, want 1", len(rows))
	}
	if !rows[0].UnknownTarget {
		t.Error("unknown_target = false, want true for a mon-client with no configuration")
	}
}
