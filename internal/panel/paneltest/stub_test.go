package paneltest_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/SBKubric/3ax-ui-monitoring/internal/panel"
	"github.com/SBKubric/3ax-ui-monitoring/internal/panel/paneltest"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
)

// contractInbounds is the pair of inbounds the contract's own §4.1 example
// shows, reused by the revision tests so the canonical document under test
// has the shape the contract documents.
func contractInbounds() []panel.Inbound {
	return []panel.Inbound{
		{Kind: "xray", InboundId: 12, Tag: "inbound-443", Remark: "Reality main", Protocol: "vless", Port: 443, Enable: true},
		{Kind: "awg", InboundId: 0, Tag: "awg", Remark: "AmneziaWG", Protocol: "awg", Port: 51820, Enable: true},
	}
}

// do sends one request to the stub with the bearer the stub expects, unless
// token is overridden.
func do(t *testing.T, s *paneltest.Stub, method, route, token string, body any) (*http.Response, []byte) {
	t.Helper()
	var r io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		r = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, strings.TrimRight(s.URL(), "/")+"/mon/v1"+route, r)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, route, err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp, raw
}

// TestStub_RevisionMatchesContractFormula pins the stub's revision to
// contract §4.2's formula, computed here independently: the first 16 hex of
// the SHA-256 of the canonical JSON with sorted keys, no whitespace,
// inbounds sorted by (kind, inboundId) and reduced to the fields that affect
// targets, plus the probe material (contract 2: no items programmed here, so
// an empty object). Every other test that asserts "the revision changed" is only
// meaningful because this one holds.
func TestStub_RevisionMatchesContractFormula(t *testing.T) {
	s := paneltest.NewStub(t)
	s.SetOverride(true, "front.example.net")
	s.SetInbounds(contractInbounds())
	sub := "k3j9d8s7f6g5h4j3"
	s.SetProbeSubID(&sub)

	canonical := `{"inbounds":[` +
		`{"enable":true,"inboundId":0,"kind":"awg","port":51820,"protocol":"awg"},` +
		`{"enable":true,"inboundId":12,"kind":"xray","port":443,"protocol":"vless"}],` +
		`"items":{},` +
		`"override":{"enabled":true,"host":"front.example.net"},` +
		`"probeSubId":"k3j9d8s7f6g5h4j3"}`
	sum := sha256.Sum256([]byte(canonical))
	want := hex.EncodeToString(sum[:])[:16]

	if got := s.Revision(); got != want {
		t.Fatalf("Revision() = %q, want %q (sha256 of %s)", got, want, canonical)
	}
	if len(want) != 16 {
		t.Fatalf("revision length = %d, want 16 (contract §4.2)", len(want))
	}
}

// TestStub_RevisionCoversProbePeers checks contract 2's revision rule
// (decision #80 п. 8): the probe material is part of the revision, so a new
// AWG probe peer — another mon-client's item on a path — moves it, and
// mon-server re-reads the configs.
func TestStub_RevisionCoversProbePeers(t *testing.T) {
	s := paneltest.NewStub(t)
	s.SetInbounds(contractInbounds())
	s.SetItems("direct", []panel.ProbeItem{paneltest.AwgItem("ams-1", "conf-a")})
	before := s.Revision()

	s.SetItems("direct", []panel.ProbeItem{paneltest.AwgItem("ams-1", "conf-a"), paneltest.AwgItem("fra-1", "conf-b")})
	if after := s.Revision(); after == before {
		t.Fatal("revision did not change when a probe peer was added")
	}
}

// TestStub_RevisionIgnoresRemarkAndTag checks the other half of contract
// §4.2: renaming an inbound must not change the revision, because a rename
// changes no target.
func TestStub_RevisionIgnoresRemarkAndTag(t *testing.T) {
	s := paneltest.NewStub(t)
	s.SetInbounds(contractInbounds())
	before := s.Revision()

	renamed := contractInbounds()
	renamed[0].Remark = "Something else entirely"
	renamed[0].Tag = "inbound-renamed"
	s.SetInbounds(renamed)

	if after := s.Revision(); after != before {
		t.Fatalf("revision changed on rename: %q → %q", before, after)
	}

	disabled := contractInbounds()
	disabled[0].Enable = false
	s.SetInbounds(disabled)
	if after := s.Revision(); after == before {
		t.Fatal("revision did not change when an inbound was disabled")
	}
}

// TestStub_BareNotFoundWithoutToken checks contract §2: no token, a wrong
// token or monitoring switched off all get a bare 404 with no body, so the
// panel never admits the API is there.
func TestStub_BareNotFoundWithoutToken(t *testing.T) {
	s := paneltest.NewStub(t)

	for _, tc := range []struct {
		name  string
		token string
	}{
		{"no token", ""},
		{"wrong token", "not-the-token"},
		{"wrong case", strings.ToUpper(s.Token())},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, body := do(t, s, http.MethodGet, "/state", tc.token, nil)
			if resp.StatusCode != http.StatusNotFound {
				t.Fatalf("status = %d, want 404", resp.StatusCode)
			}
			if len(body) != 0 {
				t.Fatalf("body = %q, want empty", body)
			}
		})
	}

	s.SetMonEnabled(false)
	resp, body := do(t, s, http.MethodGet, "/state", s.Token(), nil)
	if resp.StatusCode != http.StatusNotFound || len(body) != 0 {
		t.Fatalf("monitoring off: status = %d body = %q, want bare 404", resp.StatusCode, body)
	}
}

// TestStub_StateCarriesContractHeader checks contract §1: every successful
// answer announces X-Mon-Contract, 3 by default (decision #61 п. 5), and
// GET /state repeats it in the body.
func TestStub_StateCarriesContractHeader(t *testing.T) {
	s := paneltest.NewStub(t)
	s.SetInbounds(contractInbounds())

	resp, body := do(t, s, http.MethodGet, "/state", s.Token(), nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Mon-Contract"); got != "3" {
		t.Fatalf("X-Mon-Contract = %q, want \"3\"", got)
	}

	var st panel.State
	if err := json.Unmarshal(body, &st); err != nil {
		t.Fatalf("decode state: %v", err)
	}
	if st.Contract != 3 {
		t.Fatalf("state.contract = %d, want 3", st.Contract)
	}
	if st.Chain != nil {
		t.Fatalf("state.chain = %+v, want absent while the chain registry is empty", st.Chain)
	}
	if st.Revision != s.Revision() {
		t.Fatalf("state.revision = %q, want %q", st.Revision, s.Revision())
	}
	if len(st.Inbounds) != 2 {
		t.Fatalf("state.inbounds = %d, want 2", len(st.Inbounds))
	}
}

// TestStub_ProbeConfigsConflicts checks the two 409s of contract §4.4: no
// probe set yet, and the proxy path asked for while the override is off.
func TestStub_ProbeConfigsConflicts(t *testing.T) {
	s := paneltest.NewStub(t)

	resp, body := do(t, s, http.MethodGet, "/probe/configs", s.Token(), nil)
	if resp.StatusCode != http.StatusConflict || !strings.Contains(string(body), "probe_not_ensured") {
		t.Fatalf("before ensure: status = %d body = %s, want 409 probe_not_ensured", resp.StatusCode, body)
	}

	if resp, _ := do(t, s, http.MethodPost, "/probe/ensure", s.Token(),
		map[string]any{"monClients": []any{}}); resp.StatusCode != http.StatusOK {
		t.Fatalf("ensure status = %d, want 200", resp.StatusCode)
	}

	resp, body = do(t, s, http.MethodGet, "/probe/configs", s.Token(), nil)
	if resp.StatusCode != http.StatusConflict || !strings.Contains(string(body), "override_disabled") {
		t.Fatalf("override off: status = %d body = %s, want 409 override_disabled", resp.StatusCode, body)
	}

	resp, _ = do(t, s, http.MethodGet, "/probe/configs?host=real.example.net", s.Token(), nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("direct path status = %d, want 200", resp.StatusCode)
	}
}

// TestStub_EnsureAllocatesSubIDAndRecordsSnapshot checks contract §4.3: the
// first ensure allocates the subId the whole probe set lives under, and the
// body is recorded as the registry snapshot the panel caches.
func TestStub_EnsureAllocatesSubIDAndRecordsSnapshot(t *testing.T) {
	s := paneltest.NewStub(t)
	snapshot := []panel.MonClientSnapshot{
		{Id: "ams-1", Name: "Amsterdam #1", Region: "NL", State: "ONLINE", LastHeartbeat: 1757721590000},
	}

	resp, body := do(t, s, http.MethodPost, "/probe/ensure", s.Token(),
		map[string]any{"monClients": snapshot})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var res panel.EnsureResult
	if err := json.Unmarshal(body, &res); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if res.SubId == "" {
		t.Fatal("ensure did not allocate a subId")
	}
	if res.Revision != s.Revision() {
		t.Fatalf("ensure revision = %q, want %q", res.Revision, s.Revision())
	}

	ensured := s.Ensured()
	if len(ensured) != 1 || len(ensured[0]) != 1 || ensured[0][0].Id != "ams-1" {
		t.Fatalf("Ensured() = %+v, want the one snapshot that was sent", ensured)
	}
}

// TestStub_ContractTwoShapes checks the wire shapes of contract 2 (decision
// #80 п. 7, 9, 10): AWG items carry their mon-client's id and xray items do
// not, ensure names the mon-clients left without a peer, and SetContract
// turns the stub into an older panel on both the header and /state.
func TestStub_ContractTwoShapes(t *testing.T) {
	s := paneltest.NewStub(t)
	s.SetInbounds(contractInbounds())
	s.SetItems("direct", []panel.ProbeItem{
		{Kind: "xray", InboundId: 12, Link: "vless://x@real:443"},
		paneltest.AwgItem("ams-1", "[Interface]\n"),
	})
	s.SetUnallocated([]panel.Unallocated{{MonClientId: "fra-1", Path: "direct", Reason: "pool_exhausted"}})

	resp, body := do(t, s, http.MethodPost, "/probe/ensure", s.Token(),
		map[string]any{"monClients": []panel.MonClientSnapshot{{Id: "ams-1"}, {Id: "fra-1"}}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("ensure status = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(string(body), `"unallocated":[{"monClientId":"fra-1","path":"direct","reason":"pool_exhausted"}]`) {
		t.Fatalf("ensure body = %s, want unallocated fra-1 × direct, pool_exhausted", body)
	}

	_, body = do(t, s, http.MethodGet, "/probe/configs?host=real", s.Token(), nil)
	var raw struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatalf("decode configs: %v", err)
	}
	if len(raw.Items) != 2 {
		t.Fatalf("items = %s, want 2", body)
	}
	if _, has := raw.Items[0]["monClientId"]; has {
		t.Fatalf("xray item carries monClientId: %v", raw.Items[0])
	}
	if raw.Items[1]["monClientId"] != "ams-1" {
		t.Fatalf("awg item monClientId = %v, want ams-1", raw.Items[1]["monClientId"])
	}

	s.SetContract(1)
	resp, body = do(t, s, http.MethodGet, "/state", s.Token(), nil)
	if got := resp.Header.Get("X-Mon-Contract"); got != "1" {
		t.Fatalf("X-Mon-Contract = %q, want \"1\"", got)
	}
	var st panel.State
	if err := json.Unmarshal(body, &st); err != nil {
		t.Fatalf("decode state: %v", err)
	}
	if st.Contract != 1 {
		t.Fatalf("state.contract = %d, want 1", st.Contract)
	}
}

// TestStub_EventsDedupeByID checks contract §4.6: a repeated id is counted
// as a duplicate rather than stored twice or rejected, which is what makes
// resending an unconfirmed outbox batch safe.
func TestStub_EventsDedupeByID(t *testing.T) {
	s := paneltest.NewStub(t)
	ev := store.EventPayload{ID: "019254a0-7c3e-7d2a-9b4f-1f2e3d4c5b6a", Ts: 1757721540000,
		Kind: "panel", From: "PANEL_UP", To: "PANEL_DOWN", Reason: "http_timeout", Notified: true}

	_, body := do(t, s, http.MethodPost, "/events", s.Token(), map[string]any{"events": []any{ev}})
	var first panel.EventsResult
	if err := json.Unmarshal(body, &first); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if first.Accepted != 1 || first.Duplicates != 0 {
		t.Fatalf("first post = %+v, want accepted 1 duplicates 0", first)
	}

	_, body = do(t, s, http.MethodPost, "/events", s.Token(), map[string]any{"events": []any{ev}})
	var second panel.EventsResult
	if err := json.Unmarshal(body, &second); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if second.Accepted != 0 || second.Duplicates != 1 {
		t.Fatalf("second post = %+v, want accepted 0 duplicates 1", second)
	}

	if got := s.Events(); len(got) != 1 {
		t.Fatalf("Events() = %d rows, want 1", len(got))
	}
}

// TestStub_StatsUpsertByKey checks contract §4.7: the five-field key
// identifies a bucket, and a repeat replaces it rather than adding a row.
func TestStub_StatsUpsertByKey(t *testing.T) {
	s := paneltest.NewStub(t)
	stat := panel.StatPayload{MonClientId: "ams-1", InboundKind: "xray", InboundId: 12,
		Path: "proxy", BucketStart: 1757721300000, NOk: 5}

	do(t, s, http.MethodPost, "/stats", s.Token(), map[string]any{"stats": []any{stat}})
	stat.NOk = 9
	do(t, s, http.MethodPost, "/stats", s.Token(), map[string]any{"stats": []any{stat}})

	got := s.Stats()
	if len(got) != 1 {
		t.Fatalf("Stats() = %d rows, want 1 (upsert by key)", len(got))
	}
	if got[0].NOk != 9 {
		t.Fatalf("nOk = %d, want 9 (the second post must replace the first)", got[0].NOk)
	}
}

// TestStub_BatchTooLarge checks the limits of contract §3 — over them the
// panel answers 413 batch_too_large and stores nothing.
func TestStub_BatchTooLarge(t *testing.T) {
	s := paneltest.NewStub(t)

	events := make([]store.EventPayload, 1001)
	for i := range events {
		events[i].ID = fmt.Sprintf("id-%d", i)
	}
	resp, body := do(t, s, http.MethodPost, "/events", s.Token(), map[string]any{"events": events})
	if resp.StatusCode != http.StatusRequestEntityTooLarge || !strings.Contains(string(body), "batch_too_large") {
		t.Fatalf("1001 events: status = %d body = %s, want 413 batch_too_large", resp.StatusCode, body)
	}
	if len(s.Events()) != 0 {
		t.Fatal("an over-limit batch must not be stored")
	}

	stats := make([]panel.StatPayload, 2001)
	resp, _ = do(t, s, http.MethodPost, "/stats", s.Token(), map[string]any{"stats": stats})
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("2001 stats: status = %d, want 413", resp.StatusCode)
	}
}

// TestStub_UnknownRouteIsNotFoundWithBody checks the other 404 of contract
// §3: an authenticated caller asking for a route that does not exist gets
// the error body, which is how the client tells it from the bare refusal.
func TestStub_UnknownRouteIsNotFoundWithBody(t *testing.T) {
	s := paneltest.NewStub(t)
	resp, body := do(t, s, http.MethodGet, "/nope", s.Token(), nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
	if !strings.Contains(string(body), "not_found") {
		t.Fatalf("body = %s, want a contract error body", body)
	}
}

// TestStub_RequestsAreRecorded checks the recorder other packages' tests
// assert on: method, path including the webBasePath, query and headers.
func TestStub_RequestsAreRecorded(t *testing.T) {
	s := paneltest.NewStub(t)
	do(t, s, http.MethodGet, "/probe/configs?host=real.example.net", s.Token(), nil)

	reqs := s.Requests()
	if len(reqs) != 1 {
		t.Fatalf("Requests() = %d, want 1", len(reqs))
	}
	r := reqs[0]
	if r.Method != http.MethodGet {
		t.Fatalf("method = %q", r.Method)
	}
	if !strings.HasSuffix(r.Path, "/mon/v1/probe/configs") || !strings.HasPrefix(r.Path, "/panel/") {
		t.Fatalf("path = %q, want the webBasePath plus the contract path", r.Path)
	}
	if got := r.Query.Get("host"); got != "real.example.net" {
		t.Fatalf("query host = %q", got)
	}
	if got := r.Header.Get("Authorization"); got != "Bearer "+s.Token() {
		t.Fatalf("Authorization = %q", got)
	}
}

// TestStub_EventsRejectedPerElement pins the stub to the contract's event
// dictionary (§4.6, decision #50): each invalid element is answered in
// rejected by its index and id while the valid ones around it are accepted.
// A mon_client transition from NEVER is the regression this exists for —
// NEVER is mon-server's internal registry state, and the panel only knows
// ONLINE/OFFLINE (with an empty from for a client's first transition).
func TestStub_EventsRejectedPerElement(t *testing.T) {
	s := paneltest.NewStub(t)
	inbound := 12
	target := func(id, path, from, to string) store.EventPayload {
		return store.EventPayload{ID: id, Ts: 1757721540000, Kind: "target", MonClientID: "ams-1",
			InboundKind: "xray", InboundID: &inbound, Path: path, From: from, To: to, Reason: "tcp_timeout"}
	}
	mc := func(id, from, to string) store.EventPayload {
		return store.EventPayload{ID: id, Ts: 1757721540000, Kind: "mon_client", MonClientID: "ams-1", From: from, To: to}
	}
	events := []store.EventPayload{
		mc("e0", "", "ONLINE"),      // first transition: empty from is legal
		mc("e1", "NEVER", "ONLINE"), // NEVER never leaves mon-server
		target("e2", "edge:ams-1", "UP", "DOWN"),
		target("e3", "inner:core-1", "", "UNKNOWN"),
		target("e4", "sideways", "UP", "DOWN"), // not in the path grammar
		target("e5", "edge:Bad_Name", "UP", "DOWN"),
		target("e6", "direct", "UP", "SIDEWAYS"),
		{ID: "e7", Ts: 1757721540000, Kind: "panel", From: "PANEL_UP", To: "PANEL_DOWN", Notified: true},
		{ID: "e8", Ts: 1757721540000, Kind: "bogus", To: "UP"},
	}

	resp, body := do(t, s, http.MethodPost, "/events", s.Token(), map[string]any{"events": events})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 with per-element rejections, body=%s", resp.StatusCode, body)
	}
	var res panel.EventsResult
	if err := json.Unmarshal(body, &res); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if res.Accepted != 4 {
		t.Fatalf("accepted = %d, want 4 (e0, e2, e3, e7), body=%s", res.Accepted, body)
	}
	wantRejected := map[int]string{1: "e1", 4: "e4", 5: "e5", 6: "e6", 8: "e8"}
	if len(res.Rejected) != len(wantRejected) {
		t.Fatalf("rejected = %+v, want indices 1, 4, 5, 6, 8", res.Rejected)
	}
	for _, r := range res.Rejected {
		if wantRejected[r.Index] != r.Id || r.Error == "" {
			t.Fatalf("rejected entry %+v does not name a rejected element with a reason", r)
		}
	}
	if got := s.Events(); len(got) != 4 {
		t.Fatalf("Events() = %d rows, want only the 4 accepted", len(got))
	}
	if got := s.RejectedEvents(); len(got) != len(wantRejected) {
		t.Fatalf("RejectedEvents() = %+v, want the same %d rejections", got, len(wantRejected))
	}
}

// TestStub_StatsRejectedPerElement is the /stats half of the same rule
// (contract §4.7): a row whose path is outside the grammar is rejected by
// index, the rest are upserted.
func TestStub_StatsRejectedPerElement(t *testing.T) {
	s := paneltest.NewStub(t)
	stat := func(path string) panel.StatPayload {
		return panel.StatPayload{MonClientId: "ams-1", InboundKind: "xray", InboundId: 12,
			Path: path, BucketStart: 1757721300000, NOk: 1}
	}

	_, body := do(t, s, http.MethodPost, "/stats", s.Token(),
		map[string]any{"stats": []any{stat("direct"), stat("nowhere"), stat("inner:core-1")}})
	var res panel.StatsResult
	if err := json.Unmarshal(body, &res); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if res.Accepted != 2 || len(res.Rejected) != 1 || res.Rejected[0].Index != 1 || res.Rejected[0].Error == "" {
		t.Fatalf("result = %+v, want 2 accepted and index 1 rejected with a reason", res)
	}
	if got := s.Stats(); len(got) != 2 {
		t.Fatalf("Stats() = %d rows, want the 2 accepted", len(got))
	}
	if got := s.RejectedStats(); len(got) != 1 {
		t.Fatalf("RejectedStats() = %+v, want the one rejection", got)
	}
}

// TestStub_LegacyAnswersAreEmpty covers the stub's "old panel" mode: POST
// /events and /stats answer 200 with no body at all, which mon-server must
// read as "everything accepted".
func TestStub_LegacyAnswersAreEmpty(t *testing.T) {
	s := paneltest.NewStub(t)
	s.SetLegacyAnswers(true)
	ev := store.EventPayload{ID: "e0", Ts: 1757721540000, Kind: "panel", From: "PANEL_UP", To: "PANEL_DOWN"}

	resp, body := do(t, s, http.MethodPost, "/events", s.Token(), map[string]any{"events": []any{ev}})
	if resp.StatusCode != http.StatusOK || len(bytes.TrimSpace(body)) != 0 {
		t.Fatalf("status = %d body = %q, want 200 with an empty body", resp.StatusCode, body)
	}
	if got := s.Events(); len(got) != 1 {
		t.Fatalf("Events() = %d rows, want the event stored", len(got))
	}
}

// chainHops is a chain registry with every state a hop can be in: two
// joined edges given out of name order, a legacy inner, a joined inner, and
// one pending and one draining hop that the panel does not probe.
func chainHops() []paneltest.Hop {
	return []paneltest.Hop{
		{Name: "edge-b", Role: "edge", Host: "b.example.net", State: "joined"},
		{Name: "core-2", Role: "inner", Host: "10.0.0.8", State: "joined"},
		{Name: "edge-a", Role: "edge", Host: "a.example.net", State: "joined"},
		{Name: "core-1", Role: "inner", Host: "10.0.0.7", State: "legacy"},
		{Name: "edge-new", Role: "edge", Host: "n.example.net", State: "pending"},
		{Name: "edge-old", Role: "edge", Host: "o.example.net", State: "draining"},
	}
}

// TestStub_StateCarriesChain checks contract 3 §4.1: /state carries the
// chain with only its joined and legacy hops — inner ones first in chain
// order, then the edges by name — plus the active edge and the chain's own
// revision, and a chain change moves the contract revision (§4.2).
func TestStub_StateCarriesChain(t *testing.T) {
	s := paneltest.NewStub(t)
	s.SetInbounds(contractInbounds())
	before := s.Revision()
	s.SetChain("edge-a", chainHops())

	_, body := do(t, s, http.MethodGet, "/state", s.Token(), nil)
	var st panel.State
	if err := json.Unmarshal(body, &st); err != nil {
		t.Fatalf("decode state: %v", err)
	}
	if st.Chain == nil {
		t.Fatalf("state = %s, want a chain", body)
	}
	var got []string
	for _, h := range st.Chain.Hops {
		got = append(got, h.Role+":"+h.Name+"@"+h.Host+"/"+h.State)
	}
	want := "inner:core-2@10.0.0.8/joined,inner:core-1@10.0.0.7/legacy,edge:edge-a@a.example.net/joined,edge:edge-b@b.example.net/joined"
	if strings.Join(got, ",") != want {
		t.Fatalf("chain.hops = %v, want %s", got, want)
	}
	if st.Chain.ActiveEdge == nil || *st.Chain.ActiveEdge != "edge-a" {
		t.Fatalf("chain.activeEdge = %v, want edge-a", st.Chain.ActiveEdge)
	}
	if st.Chain.Revision == 0 {
		t.Fatal("chain.revision = 0, want the registry's counter")
	}

	withChain := s.Revision()
	if withChain == before {
		t.Fatal("revision did not move when the chain appeared")
	}
	s.SetChain("edge-b", chainHops())
	if s.Revision() == withChain {
		t.Fatal("revision did not move when the active edge switched")
	}

	// An active edge that is pending is not among the hops (contract §4.1).
	s.SetChain("edge-new", chainHops())
	_, body = do(t, s, http.MethodGet, "/state", s.Token(), nil)
	st = panel.State{}
	if err := json.Unmarshal(body, &st); err != nil {
		t.Fatalf("decode state: %v", err)
	}
	if st.Chain.ActiveEdge == nil || *st.Chain.ActiveEdge != "edge-new" || len(st.Chain.Hops) != 4 {
		t.Fatalf("chain = %+v, want the pending active edge named but not listed", st.Chain)
	}
}

// TestStub_HopConfigs checks contract 3 §4.4: ?hop=<name> (and its synonym
// ?edge=) renders the path of that hop by its role, an unknown name — or a
// hop and an edge that disagree — is 409 unknown_hop, and a hop that is in
// the registry but not joined or legacy is 409 hop_not_joined.
func TestStub_HopConfigs(t *testing.T) {
	s := paneltest.NewStub(t)
	s.SetChain("edge-a", chainHops())
	s.SetItems("edge:edge-a", []panel.ProbeItem{{Kind: "xray", InboundId: 12, Link: "vless://x@a.example.net:443"}})
	s.SetItems("inner:core-1", []panel.ProbeItem{{Kind: "xray", InboundId: 12, Link: "vless://x@10.0.0.7:443"}})
	if resp, _ := do(t, s, http.MethodPost, "/probe/ensure", s.Token(), map[string]any{"monClients": []any{}}); resp.StatusCode != http.StatusOK {
		t.Fatalf("ensure status = %d", resp.StatusCode)
	}

	for _, tc := range []struct{ query, path, link string }{
		{"hop=edge-a", "edge:edge-a", "vless://x@a.example.net:443"},
		{"edge=edge-a", "edge:edge-a", "vless://x@a.example.net:443"},
		{"hop=core-1", "inner:core-1", "vless://x@10.0.0.7:443"},
		{"hop=edge-a&edge=edge-a", "edge:edge-a", "vless://x@a.example.net:443"},
	} {
		resp, body := do(t, s, http.MethodGet, "/probe/configs?"+tc.query, s.Token(), nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: status = %d body = %s", tc.query, resp.StatusCode, body)
		}
		var pc panel.ProbeConfigs
		if err := json.Unmarshal(body, &pc); err != nil {
			t.Fatalf("%s: decode: %v", tc.query, err)
		}
		if pc.Path != tc.path || len(pc.Items) != 1 || pc.Items[0].Link != tc.link || pc.Revision != s.Revision() {
			t.Fatalf("%s: answer = %+v, want path %s with %s at the current revision", tc.query, pc, tc.path, tc.link)
		}
	}

	for _, tc := range []struct{ query, code string }{
		{"hop=nope", "unknown_hop"},
		{"hop=edge-a&edge=edge-b", "unknown_hop"},
		{"hop=edge-new", "hop_not_joined"},
		{"edge=edge-old", "hop_not_joined"},
	} {
		resp, body := do(t, s, http.MethodGet, "/probe/configs?"+tc.query, s.Token(), nil)
		if resp.StatusCode != http.StatusConflict || !strings.Contains(string(body), tc.code) {
			t.Fatalf("%s: status = %d body = %s, want 409 %s", tc.query, resp.StatusCode, body, tc.code)
		}
	}
}

// TestStub_EnsureRecordsPaths checks contract 3 §4.3: the snapshot carries
// each mon-client's paths vocabulary, and the stub keeps it for a test to
// assert on.
func TestStub_EnsureRecordsPaths(t *testing.T) {
	s := paneltest.NewStub(t)
	snapshot := []panel.MonClientSnapshot{
		{Id: "ams-1", State: "ONLINE", Paths: []string{"direct", "hops"}},
		{Id: "msk-1", State: "NEVER", Paths: []string{"edge:edge-a", "inner:core-1"}},
	}
	if resp, body := do(t, s, http.MethodPost, "/probe/ensure", s.Token(), map[string]any{"monClients": snapshot}); resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d body = %s", resp.StatusCode, body)
	}
	ensured := s.Ensured()
	if len(ensured) != 1 || strings.Join(ensured[0][1].Paths, ",") != "edge:edge-a,inner:core-1" {
		t.Fatalf("Ensured() = %+v, want the paths as sent", ensured)
	}
}
