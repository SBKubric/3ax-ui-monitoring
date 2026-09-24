// Package paneltest is an httptest implementation of the panel's mon-server
// contract (docs/spec/monitoring-contract.md in the panel repo). It exists
// because every part of mon-server that talks to the panel — the poll cycle
// here, the config builder in step 5, the stats flush in step 7 — has to be
// testable without a panel, and because a hand-rolled fake per package would
// drift from the contract one package at a time.
//
// The stub is deliberately strict about the things the contract makes
// normative: the bearer check answers a bare 404 exactly as the panel's
// checkMonAuth does, every success carries X-Mon-Contract, the revision is
// computed with the real formula (§4.2) rather than being a string a test
// hands out, the batch limits are enforced, and every event and stat row is
// checked against the contract's dictionary — from/to per kind, the path
// grammar — and answered element by element (decision #50), so a value
// mon-server must never send (a mon_client transition from NEVER) fails a
// test instead of a production panel. It is deliberately lax about
// everything else — it does not create probe accounts, it does not check
// reasons, ids or timestamps — because those are the panel's job, not what
// mon-server's tests need to pin.
package paneltest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/panel"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
)

const (
	// basePath is the panel's webBasePath as the stub serves it. It is
	// deliberately not "/": a test that hands Stub.URL() to the client
	// proves the client joins the contract path onto a real base path
	// instead of assuming the panel sits at the root (contract §1).
	basePath = "/panel/"

	// token is the stub's monToken. It is a fixed 32-character string like
	// the panel's own (contract §2) rather than a random one so that a
	// failing test prints something recognisable.
	token = "paneltest-mon-token-0123456789ab"

	// revisionHexLen is how much of the SHA-256 the revision keeps
	// (contract §4.2: "первые 16 hex-символов").
	revisionHexLen = 16

	// maxBodyBytes, maxEvents, maxStats and maxMonClients are the contract's
	// limits (§3); exceeding any of them is 413 batch_too_large.
	maxBodyBytes  = 1 << 20
	maxEvents     = 1000
	maxStats      = 2000
	maxMonClients = 200

	// staleThresholdMinutes is what the stub reports in /state's stale
	// block (contract §5: monStaleMinutes defaults to 15). mon-server does
	// not act on it in v1; it is here so the field is not zero.
	staleThresholdMinutes = 15
)

// The contract's dictionary for events and stats (§4.6, §4.7, decision
// #50). An empty from is legal for every kind — it is how a first
// transition is spelled — and NEVER is deliberately absent from the
// mon_client states: it is mon-server's internal registry state and never
// leaves it.
var (
	eventStates = map[string]map[string]bool{
		"target":     {"UP": true, "DOWN": true, "FLAPPING": true, "UNKNOWN": true, "PAUSED": true},
		"mon_client": {"ONLINE": true, "OFFLINE": true},
		"panel":      {"PANEL_UP": true, "PANEL_DOWN": true},
	}

	// pathRe is the path grammar: direct, proxy, or a chain hop by name
	// (proxy-chain §6, hop names [a-z0-9-]{1,32}).
	pathRe = regexp.MustCompile(`^(direct|proxy|(edge|inner):[a-z0-9-]{1,32})$`)
)

// RecordedRequest is one request the stub received, kept whether or not it
// was answered successfully — a test asserting "only the direct path was
// fetched" needs to see the requests that were made, including any the stub
// was told to fail.
type RecordedRequest struct {
	Method string
	// Path is the full request path as it arrived, including the stub's
	// webBasePath, so a test can assert the client joined the base path
	// correctly.
	Path   string
	Query  url.Values
	Header http.Header
	Body   []byte
}

// routeFailure is an injected failure aimed at one contract route rather
// than at the next request whatever it is. skip lets a test leave a run of
// leading requests to the route untouched before the failure window opens —
// needed to make one batch of a multi-batch call (a big POST /events drain)
// succeed and a later one fail within the same cycle, which starting the
// failure window immediately cannot express.
type routeFailure struct {
	skip   int
	n      int
	status int
}

// Stub is a programmable panel. Every knob is mutex-protected because the
// component under test usually drives it from its own goroutine while the
// test body reprograms it.
type Stub struct {
	srv *httptest.Server

	mu sync.Mutex

	monEnabled bool
	inbounds   []panel.Inbound
	override   panel.Override
	probeSubID *string

	lastEnsured int64
	items       map[string][]panel.ProbeItem
	configsRev  string // forced revision for /probe/configs; "" = the real one

	requests   []RecordedRequest
	ensured    [][]panel.MonClientSnapshot
	events     []store.EventPayload
	eventIDs   map[string]struct{}
	stats      map[string]panel.StatPayload
	statsOrder []string

	rejectedEvents []panel.Rejected
	rejectedStats  []panel.Rejected
	legacy         bool

	failN      int
	failStatus int
	failRoutes map[string]routeFailure
	dropN      int
	sleepN     int
	sleepFor   time.Duration
	badBodyN   int
}

// NewStub starts a panel stub on a loopback port and registers its shutdown
// with t. It comes up with monitoring enabled, no inbounds, no override and
// no probe set — the state of a panel an operator has just switched
// monitoring on for.
func NewStub(t testing.TB) *Stub {
	t.Helper()
	s := newStub()
	s.srv = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.srv.Close)
	return s
}

// NewTLSStub is NewStub served over HTTPS with httptest's self-signed
// certificate (IP SAN 127.0.0.1) — the shape of a stand panel on a
// certificate no system CA knows, which is what the panelCa setting is for
// (decision #52 §1). CertPEM hands that certificate to a test as the PEM an
// operator would paste.
func NewTLSStub(t testing.TB) *Stub {
	t.Helper()
	s := newStub()
	s.srv = httptest.NewTLSServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.srv.Close)
	return s
}

// CertPEM is the stub's own TLS certificate in PEM, or "" for a plain-HTTP
// stub from NewStub.
func (s *Stub) CertPEM() string {
	if s.srv.Certificate() == nil {
		return ""
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.srv.Certificate().Raw}))
}

func newStub() *Stub {
	return &Stub{
		monEnabled: true,
		items:      map[string][]panel.ProbeItem{},
		failRoutes: map[string]routeFailure{},
		eventIDs:   map[string]struct{}{},
		stats:      map[string]panel.StatPayload{},
	}
}

// URL is the base URL to hand to panel.NewHTTPClient: the stub's origin plus
// a webBasePath, exactly the shape an operator types into the settings page
// (§9.4).
func (s *Stub) URL() string { return s.srv.URL + basePath }

// Token is the bearer the stub accepts; anything else gets the bare 404 of
// contract §2.
func (s *Stub) Token() string { return token }

// SetInbounds replaces the inbound list GET /state reports, which also
// changes the revision (contract §4.2).
func (s *Stub) SetInbounds(in []panel.Inbound) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.inbounds = append([]panel.Inbound(nil), in...)
}

// SetOverride sets the panel's host override. With enabled false the
// contract requires the host to be empty, and the stub enforces that so a
// test cannot accidentally depend on a state the panel cannot produce.
func (s *Stub) SetOverride(enabled bool, host string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !enabled {
		host = ""
	}
	s.override = panel.Override{Enabled: enabled, Host: host}
}

// SetProbeSubID sets (or with nil clears) the probe set's subId. Clearing it
// puts the panel back in the "probe set never created" state, where
// /probe/configs answers 409 probe_not_ensured.
func (s *Stub) SetProbeSubID(id *string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id == nil {
		s.probeSubID = nil
		return
	}
	v := *id
	s.probeSubID = &v
}

// SetItems programs what GET /probe/configs returns for one path, "proxy" or
// "direct".
func (s *Stub) SetItems(path string, items []panel.ProbeItem) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items[path] = append([]panel.ProbeItem(nil), items...)
}

// SetConfigsRevision forces GET /probe/configs to answer with a revision
// other than the current one, so a test can exercise the "answer belongs to
// a state we have already moved past" rule (spec §4 step 3) without having
// to win a race against the poller. Passing "" restores the real revision.
func (s *Stub) SetConfigsRevision(rev string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.configsRev = rev
}

// SetMonEnabled switches monitoring off or on. With it off every route
// answers a bare 404 (contract §2), which is what mon-server sees when an
// operator disables monitoring or rotates monToken.
func (s *Stub) SetMonEnabled(on bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.monEnabled = on
}

// Revision is the revision the stub currently reports, computed with the
// contract's own formula (§4.2) from the programmed override, inbounds and
// probe subId — so a test can assert that mon-server reacted to a real
// revision change rather than to a label the stub made up.
func (s *Stub) Revision() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.revisionLocked()
}

// FailNext makes the next n requests fail with the given status. A status of
// 404 is answered bare, like the panel's auth refusal; a status of 0 drops
// the connection instead, which is what a network failure looks like to the
// client; anything else is answered with the contract's error body (§3).
func (s *Stub) FailNext(n, status int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if status == 0 {
		s.dropN += n
		return
	}
	s.failN = n
	s.failStatus = status
}

// FailNextOn makes the next n requests to one route — "/state",
// "/probe/ensure", "/probe/configs", "/events", "/stats", named without the
// webBasePath and the contract prefix — fail with the given status, while
// every other route keeps working. A whole cycle touches several routes, so
// this is the only way to test what one of them failing does.
func (s *Stub) FailNextOn(route string, n, status int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failRoutes[route] = routeFailure{n: n, status: status}
}

// FailNextOnAfter is FailNextOn with a leading run of `skip` requests to
// route left untouched before the n failures start. It exists for a drain
// that sends several batches to the same route in one cycle (POST /events
// past the 1000-item limit): a test can let the first batch or two succeed
// and only the next one fail, which FailNextOn's "starting immediately"
// cannot express.
func (s *Stub) FailNextOnAfter(route string, skip, n, status int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failRoutes[route] = routeFailure{skip: skip, n: n, status: status}
}

// DropNext hijacks and closes the connection for the next n requests,
// producing a transport error (spec §4.1's conn_refused) rather than an HTTP
// status.
func (s *Stub) DropNext(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dropN += n
}

// SleepNext holds the next n requests for d before answering, so a test can
// make the client's timeout fire (spec §4.1's http_timeout). The sleep ends
// early if the client hangs up, so it never delays the stub's own shutdown.
func (s *Stub) SleepNext(n int, d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sleepN = n
	s.sleepFor = d
}

// BadBodyNext makes the next n requests, whichever route they hit, answer
// 200 OK with a body that is not the contract's JSON — the shape of a
// captive portal or a misconfigured reverse proxy intercepting the
// connection ahead of the panel entirely, which is why it is checked before
// auth like FailNext and DropNext: the thing answering has never seen the
// bearer token. It exists to test the client's ErrBadBody path (spec §4
// PLAUSIBLE finding) without a real network in front of it.
func (s *Stub) BadBodyNext(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.badBodyN += n
}

// SetLegacyAnswers switches POST /events and /stats to the answers of a
// panel from before per-element validation (decision #50): a valid batch
// gets a bare 200 with no body, and a batch with any invalid element is
// refused whole with 400 invalid_body.
func (s *Stub) SetLegacyAnswers(on bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.legacy = on
}

// RejectedEvents returns every rejection POST /events answered with, in
// arrival order across all batches, so a test can assert both that
// mon-server sent nothing outside the dictionary and that a rejected event
// was not offered again.
func (s *Stub) RejectedEvents() []panel.Rejected {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]panel.Rejected(nil), s.rejectedEvents...)
}

// RejectedStats is RejectedEvents for POST /stats.
func (s *Stub) RejectedStats() []panel.Rejected {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]panel.Rejected(nil), s.rejectedStats...)
}

// Requests returns every request the stub saw, in arrival order.
func (s *Stub) Requests() []RecordedRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]RecordedRequest(nil), s.requests...)
}

// Events returns every event POST /events accepted, in arrival order.
// Duplicates by id are not repeated here — they are only counted, exactly as
// the panel counts them (contract §4.6).
func (s *Stub) Events() []store.EventPayload {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]store.EventPayload(nil), s.events...)
}

// Stats returns the upserted stat rows in first-seen key order (contract
// §4.7: a repeat with the same key replaces the row, it does not add one).
func (s *Stub) Stats() []panel.StatPayload {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]panel.StatPayload, 0, len(s.statsOrder))
	for _, k := range s.statsOrder {
		out = append(out, s.stats[k])
	}
	return out
}

// Ensured returns the mon-client snapshot body of every POST /probe/ensure,
// in arrival order, so a test can assert what registry snapshot mon-server
// actually sent.
func (s *Stub) Ensured() [][]panel.MonClientSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([][]panel.MonClientSnapshot(nil), s.ensured...)
}

// revisionLocked implements contract §4.2: the first 16 hex characters of
// the SHA-256 of the canonical JSON (keys sorted, no whitespace) of the
// override, the inbounds sorted by (kind, inboundId) with only the fields
// that affect targets, and the probe subId. Marshalling maps rather than
// structs is what makes it canonical — encoding/json sorts map keys and
// emits no spaces — and remark/tag are left out so that renaming an inbound
// does not rebuild every mon-client's config.
func (s *Stub) revisionLocked() string {
	sorted := append([]panel.Inbound(nil), s.inbounds...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Kind != sorted[j].Kind {
			return sorted[i].Kind < sorted[j].Kind
		}
		return sorted[i].InboundId < sorted[j].InboundId
	})

	ins := make([]any, 0, len(sorted))
	for _, in := range sorted {
		ins = append(ins, map[string]any{
			"kind":      in.Kind,
			"inboundId": in.InboundId,
			"protocol":  in.Protocol,
			"port":      in.Port,
			"enable":    in.Enable,
		})
	}

	subID := ""
	if s.probeSubID != nil {
		subID = *s.probeSubID
	}

	raw, err := json.Marshal(map[string]any{
		"override":   map[string]any{"enabled": s.override.Enabled, "host": s.override.Host},
		"inbounds":   ins,
		"probeSubId": subID,
	})
	if err != nil {
		panic("paneltest: canonical revision document is not marshallable: " + err.Error())
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])[:revisionHexLen]
}

// serve is the whole stub: record, injected failures, auth, route. The order
// matters — failures are injected before the auth check so that a test can
// simulate an unreachable panel without first having to make the request
// valid, and requests are recorded before either so the log shows what was
// attempted.
func (s *Stub) serve(w http.ResponseWriter, r *http.Request) {
	body, tooBig := readBody(w, r)
	if tooBig {
		writeErr(w, http.StatusRequestEntityTooLarge, "batch_too_large", "body larger than 1 MiB")
		return
	}

	s.mu.Lock()
	s.requests = append(s.requests, RecordedRequest{
		Method: r.Method,
		Path:   r.URL.Path,
		Query:  r.URL.Query(),
		Header: r.Header.Clone(),
		Body:   body,
	})

	drop := s.dropN > 0
	if drop {
		s.dropN--
	}
	failStatus := 0
	if !drop && s.failN > 0 {
		s.failN--
		failStatus = s.failStatus
	}
	if !drop && failStatus == 0 {
		if route, ok := strings.CutPrefix(r.URL.Path, basePath+"mon/v1"); ok {
			if rf, injected := s.failRoutes[route]; injected {
				switch {
				case rf.skip > 0:
					rf.skip--
					s.failRoutes[route] = rf
				case rf.n > 0:
					rf.n--
					s.failRoutes[route] = rf
					failStatus = rf.status
				}
			}
		}
	}
	badBody := false
	if !drop && failStatus == 0 && s.badBodyN > 0 {
		s.badBodyN--
		badBody = true
	}
	sleepFor := time.Duration(0)
	if s.sleepN > 0 {
		s.sleepN--
		sleepFor = s.sleepFor
	}
	enabled := s.monEnabled
	s.mu.Unlock()

	if sleepFor > 0 {
		t := time.NewTimer(sleepFor)
		defer t.Stop()
		select {
		case <-t.C:
		case <-r.Context().Done():
			return
		}
	}

	if drop {
		hijackClose(w)
		return
	}
	if failStatus != 0 {
		if failStatus == http.StatusNotFound {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		writeErr(w, failStatus, injectedCode(failStatus), "injected failure")
		return
	}
	if badBody {
		// No X-Mon-Contract header and no JSON: a real captive portal or a
		// stray reverse proxy in front of panelUrl has never heard of the
		// contract, and would answer with its own page regardless of the
		// bearer token this request carried.
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body>captive portal</body></html>"))
		return
	}

	if !enabled || r.Header.Get("Authorization") != "Bearer "+token {
		// Contract §2: no token, wrong token or monitoring off is a bare
		// 404 with no body, so the panel does not reveal the API exists.
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("X-Mon-Contract", "1")

	route, ok := strings.CutPrefix(r.URL.Path, basePath+"mon/v1")
	if !ok {
		writeErr(w, http.StatusNotFound, "not_found", "unknown route "+r.URL.Path)
		return
	}

	switch {
	case r.Method == http.MethodGet && route == "/state":
		s.handleState(w)
	case r.Method == http.MethodPost && route == "/probe/ensure":
		s.handleEnsure(w, body)
	case r.Method == http.MethodGet && route == "/probe/configs":
		s.handleConfigs(w, r.URL.Query().Get("host"))
	case r.Method == http.MethodDelete && route == "/probe":
		s.handleProbeDelete(w)
	case r.Method == http.MethodPost && route == "/events":
		s.handleEvents(w, body)
	case r.Method == http.MethodPost && route == "/stats":
		s.handleStats(w, body)
	default:
		writeErr(w, http.StatusNotFound, "not_found", "unknown route "+r.Method+" "+r.URL.Path)
	}
}

func (s *Stub) handleState(w http.ResponseWriter) {
	s.mu.Lock()
	st := panel.State{
		Contract:     1,
		PanelVersion: "0.0.0-paneltest",
		ServerTime:   nowMs(),
		Revision:     s.revisionLocked(),
		Override:     s.override,
		Probe:        panel.Probe{SubId: s.probeSubID, LastEnsured: s.lastEnsured},
		Inbounds:     append([]panel.Inbound(nil), s.inbounds...),
	}
	st.Stale.ThresholdMinutes = staleThresholdMinutes
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, st)
}

func (s *Stub) handleEnsure(w http.ResponseWriter, body []byte) {
	var in struct {
		MonClients []panel.MonClientSnapshot `json:"monClients"`
	}
	if err := json.Unmarshal(body, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_body", err.Error())
		return
	}
	if len(in.MonClients) > maxMonClients {
		writeErr(w, http.StatusRequestEntityTooLarge, "batch_too_large",
			fmt.Sprintf("monClients has %d elements, limit %d", len(in.MonClients), maxMonClients))
		return
	}

	s.mu.Lock()
	if s.probeSubID == nil {
		// Contract §4.3: the panel allocates the subId on the first ensure.
		id := "paneltest-subid"
		s.probeSubID = &id
	}
	s.lastEnsured = nowMs()
	s.ensured = append(s.ensured, append([]panel.MonClientSnapshot(nil), in.MonClients...))
	res := panel.EnsureResult{
		SubId:       *s.probeSubID,
		Revision:    s.revisionLocked(),
		LastEnsured: s.lastEnsured,
		Created:     []panel.InboundRef{},
		Present:     len(s.inbounds),
	}
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, res)
}

func (s *Stub) handleConfigs(w http.ResponseWriter, host string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.probeSubID == nil {
		writeErr(w, http.StatusConflict, "probe_not_ensured", "probe set has never been created")
		return
	}

	path := "proxy"
	if host != "" {
		path = "direct"
	} else if !s.override.Enabled {
		// Contract §4.4: without the override there is no proxy front to
		// render configs for, so the proxy path simply does not exist.
		writeErr(w, http.StatusConflict, "override_disabled", "host override is off")
		return
	}

	rev := s.configsRev
	if rev == "" {
		rev = s.revisionLocked()
	}
	items := s.items[path]
	if items == nil {
		items = []panel.ProbeItem{}
	}

	writeJSON(w, http.StatusOK, panel.ProbeConfigs{Revision: rev, Path: path, Items: items})
}

func (s *Stub) handleProbeDelete(w http.ResponseWriter) {
	s.mu.Lock()
	s.probeSubID = nil
	s.lastEnsured = 0
	s.ensured = nil
	s.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (s *Stub) handleEvents(w http.ResponseWriter, body []byte) {
	var in struct {
		Events []store.EventPayload `json:"events"`
	}
	if err := json.Unmarshal(body, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_body", err.Error())
		return
	}
	if len(in.Events) > maxEvents {
		writeErr(w, http.StatusRequestEntityTooLarge, "batch_too_large",
			fmt.Sprintf("events has %d elements, limit %d", len(in.Events), maxEvents))
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	res := panel.EventsResult{Ignored: []panel.Ignored{}, Rejected: []panel.Rejected{}}
	for i, ev := range in.Events {
		if msg := validateEvent(ev); msg != "" {
			res.Rejected = append(res.Rejected, panel.Rejected{Index: i, Id: ev.ID, Error: msg})
		}
	}
	if s.legacy && len(res.Rejected) > 0 {
		r := res.Rejected[0]
		writeErr(w, http.StatusBadRequest, "invalid_body", fmt.Sprintf("events[%d].%s", r.Index, r.Error))
		return
	}
	s.rejectedEvents = append(s.rejectedEvents, res.Rejected...)
	rejected := indexSet(res.Rejected)
	for i, ev := range in.Events {
		if rejected[i] {
			continue
		}
		if _, seen := s.eventIDs[ev.ID]; seen {
			res.Duplicates++
			continue
		}
		s.eventIDs[ev.ID] = struct{}{}
		s.events = append(s.events, ev)
		res.Accepted++
	}

	s.writeBatchResult(w, res)
}

func (s *Stub) handleStats(w http.ResponseWriter, body []byte) {
	var in struct {
		Stats []panel.StatPayload `json:"stats"`
	}
	if err := json.Unmarshal(body, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_body", err.Error())
		return
	}
	if len(in.Stats) > maxStats {
		writeErr(w, http.StatusRequestEntityTooLarge, "batch_too_large",
			fmt.Sprintf("stats has %d elements, limit %d", len(in.Stats), maxStats))
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	res := panel.StatsResult{Ignored: []panel.Ignored{}, Rejected: []panel.Rejected{}}
	for i, st := range in.Stats {
		if msg := validatePath(st.Path); msg != "" {
			res.Rejected = append(res.Rejected, panel.Rejected{Index: i, Error: msg})
		}
	}
	if s.legacy && len(res.Rejected) > 0 {
		r := res.Rejected[0]
		writeErr(w, http.StatusBadRequest, "invalid_body", fmt.Sprintf("stats[%d].%s", r.Index, r.Error))
		return
	}
	s.rejectedStats = append(s.rejectedStats, res.Rejected...)
	rejected := indexSet(res.Rejected)
	for i, st := range in.Stats {
		if rejected[i] {
			continue
		}
		key := fmt.Sprintf("%s|%s|%d|%s|%d", st.MonClientId, st.InboundKind, st.InboundId, st.Path, st.BucketStart)
		if _, seen := s.stats[key]; !seen {
			s.statsOrder = append(s.statsOrder, key)
		}
		s.stats[key] = st
		res.Accepted++
	}

	s.writeBatchResult(w, res)
}

// writeBatchResult answers a POST /events or /stats that got past
// validation: the per-element result, or — in legacy mode — the bare 200
// with no body an older panel sends. Called with s.mu held; it only reads
// s.legacy.
func (s *Stub) writeBatchResult(w http.ResponseWriter, res any) {
	if s.legacy {
		w.WriteHeader(http.StatusOK)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// validateEvent checks one event against the contract's dictionary,
// returning "" for a valid one and a "field: reason" message otherwise —
// the shape the panel puts in rejected[].error.
func validateEvent(ev store.EventPayload) string {
	states, ok := eventStates[ev.Kind]
	if !ok {
		return fmt.Sprintf("kind: unknown value %q", ev.Kind)
	}
	if !states[ev.To] {
		return fmt.Sprintf("to: unknown value %q for kind %s", ev.To, ev.Kind)
	}
	if ev.From != "" && !states[ev.From] {
		return fmt.Sprintf("from: unknown value %q for kind %s", ev.From, ev.Kind)
	}
	if ev.Kind == "target" {
		return validatePath(ev.Path)
	}
	return ""
}

// validatePath checks a target's path against the grammar.
func validatePath(path string) string {
	if !pathRe.MatchString(path) {
		return fmt.Sprintf("path: unknown value %q", path)
	}
	return ""
}

// indexSet turns a rejection list into the set of rejected batch indices.
func indexSet(rej []panel.Rejected) map[int]bool {
	out := make(map[int]bool, len(rej))
	for _, r := range rej {
		out[r.Index] = true
	}
	return out
}

// readBody reads at most the contract's 1 MiB (§3), reporting separately
// that the limit was hit so the caller can answer 413 rather than 400.
func readBody(w http.ResponseWriter, r *http.Request) (body []byte, tooBig bool) {
	if r.Body == nil {
		return nil, false
	}
	defer func() { _ = r.Body.Close() }()

	buf, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	var maxErr *http.MaxBytesError
	if errors.As(err, &maxErr) {
		return buf, true
	}
	return buf, false
}

// injectedCode names the injected failure with the code the panel would use
// for that status (contract §3), so a test asserting on Code sees something
// the real panel could also have sent.
func injectedCode(status int) string {
	switch status {
	case http.StatusBadRequest:
		return "invalid_body"
	case http.StatusConflict:
		return "conflict"
	case http.StatusRequestEntityTooLarge:
		return "batch_too_large"
	case http.StatusServiceUnavailable:
		return "xray_unavailable"
	default:
		return "internal"
	}
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]string{"error": code, "message": msg})
}

// hijackClose takes the connection away from net/http and closes it without
// writing a response, which the client sees as the connection being reset —
// the closest a stub can get to a panel that is not listening.
func hijackClose(w http.ResponseWriter) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	conn, _, err := hj.Hijack()
	if err != nil {
		return
	}
	_ = conn.Close()
}

func nowMs() int64 { return time.Now().UnixMilli() }
