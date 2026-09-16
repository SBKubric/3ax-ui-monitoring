// Package paneltest serves the panel monitoring contract v1 in process, so
// that the panel client, the poll loop on top of it and the e2e harness can be
// exercised without a panel.
//
// The stub is a normal package rather than a test file: other packages' tests
// import it. It holds the state a panel would hold — the token it accepts, the
// configuration snapshot behind GET /state, the probe set, the configs per
// path — and records everything that was posted to it, behind a mutex, because
// mon-server may call it from several goroutines.
//
// It is strict where the contract is strict, and says so: an events batch
// whose items carry fields their kind does not have is a 400, as is an
// aggregate whose bucket is not a multiple of five minutes or whose latencies
// are not null with no successes. Failures a test asks for come from the
// Failure constructors and take precedence over the real answers.
package paneltest

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
	"github.com/SBKubric/3ax-ui-monitoring/internal/panel"
)

// DefaultToken is the monToken a fresh stub accepts.
const DefaultToken = "0123456789abcdef0123456789abcdef"

// DefaultRevision is the revision a fresh stub reports.
const DefaultRevision = "9f2c1a7b3e5d4c60"

// maxBodyBytes mirrors the panel's 1 MiB body limit (contract §3).
const maxBodyBytes = 1 << 20

// Request is one call the stub received, recorded in order.
type Request struct {
	Method   string
	Path     string
	Endpoint string
	Query    url.Values
	Header   http.Header
	Body     []byte
}

// Stub is an in-process panel. Create it with NewStub or New, point a
// panel.Client at URL, and read back what was posted.
type Stub struct {
	server *httptest.Server
	done   chan struct{}
	closed sync.Once

	mu             sync.Mutex
	token          string
	state          panel.State
	configs        map[string]panel.ProbeConfigs
	contractHeader string
	clk            clock.Clock
	failures       map[string]*Failure
	strictInbounds bool

	requests     []Request
	events       []panel.Event
	rawEvents    []json.RawMessage
	stats        []panel.Stat
	rawStats     []json.RawMessage
	ensures      [][]panel.MonClientSnapshot
	seenEventIDs map[string]bool
	ensured      bool
	probeDeleted bool
}

// NewStub starts a stub and stops it when the test ends.
func NewStub(tb testing.TB) *Stub {
	tb.Helper()
	s := New()
	tb.Cleanup(s.Close)
	return s
}

// New starts a stub without a testing.TB, for harnesses that have none. The
// caller must Close it.
func New() *Stub {
	s := &Stub{
		done:           make(chan struct{}),
		token:          DefaultToken,
		configs:        map[string]panel.ProbeConfigs{},
		contractHeader: "1",
		clk:            clock.System{},
		failures:       map[string]*Failure{},
		seenEventIDs:   map[string]bool{},
	}
	s.state = defaultState(clock.MS(s.clk.Now()))
	s.server = httptest.NewServer(http.HandlerFunc(s.handle))
	return s
}

// defaultState is a small but complete panel: one xray inbound and one AWG
// server, no host override, and a probe set that has never been created.
func defaultState(now int64) panel.State {
	return panel.State{
		Contract:     panel.Contract,
		PanelVersion: "1.8.1-fork.3",
		ServerTime:   now,
		Revision:     DefaultRevision,
		Override:     panel.Override{Enabled: false, Host: ""},
		Probe:        panel.ProbeState{SubID: nil, LastEnsured: 0},
		Inbounds: []panel.Inbound{
			{Kind: panel.InboundKindXray, InboundID: 12, Tag: "inbound-443", Remark: "Reality main", Protocol: "vless", Port: 443, Enable: true},
			{Kind: panel.InboundKindAWG, InboundID: 0, Tag: "awg", Remark: "AmneziaWG", Protocol: "awg", Port: 51820, Enable: true},
		},
		Stale: panel.Stale{ThresholdMinutes: 15},
	}
}

// URL is the stub's base URL, without a webBasePath. Append one to exercise a
// panel that serves under a prefix: the stub accepts any prefix before
// /mon/v1/.
func (s *Stub) URL() string { return s.server.URL }

// Close stops the stub and releases any request held open by Hanging. It is
// safe to call more than once.
func (s *Stub) Close() {
	s.closed.Do(func() {
		close(s.done)
		s.server.Close()
	})
}

// SetToken changes the monToken the stub accepts. Any other token gets the
// bare 404 of contract §2.
func (s *Stub) SetToken(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.token = token
}

// SetClock replaces the stub's time source, which stamps lastEnsured.
func (s *Stub) SetClock(c clock.Clock) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clk = c
}

// SetState replaces the whole GET /state answer. It is returned verbatim, so a
// test that depends on serverTime sets it here.
func (s *Stub) SetState(state panel.State) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = state
}

// State returns the current snapshot.
func (s *Stub) State() panel.State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}

// SetRevision changes the revision reported by GET /state and by a synthesised
// GET /probe/configs.
func (s *Stub) SetRevision(revision string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.Revision = revision
}

// SetInbounds replaces the sanitised inbound list.
func (s *Stub) SetInbounds(inbounds ...panel.Inbound) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.Inbounds = inbounds
}

// SetOverride switches the panel's host override on or off.
func (s *Stub) SetOverride(enabled bool, host string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !enabled {
		host = ""
	}
	s.state.Override = panel.Override{Enabled: enabled, Host: host}
}

// SetProbeSubID pre-creates the probe set, as if an ensure had already run.
func (s *Stub) SetProbeSubID(subID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.Probe.SubID = panel.StringPtr(subID)
	s.ensured = true
}

// SetConfigs pins the answer to GET /probe/configs for one path, which is
// panel.PathDirect when the client sends a host and panel.PathProxy when it
// does not. Without a pinned answer the stub renders the enabled inbounds of
// the current state. Give the pinned answer a revision that differs from the
// state's to exercise the stale-revision branch of spec §4 step 3.
func (s *Stub) SetConfigs(path string, configs panel.ProbeConfigs) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.configs[path] = configs
}

// SetContractHeader changes the X-Mon-Contract header on successful answers.
// The empty string omits it.
func (s *Stub) SetContractHeader(value string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.contractHeader = value
}

// SetStrictInbounds makes the stub ignore events and aggregates about an
// inbound the state does not list, as a real panel does (contract §3). It is
// off by default so that a test need not describe the inbounds it uses.
func (s *Stub) SetStrictInbounds(strict bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.strictInbounds = strict
}

// Fail makes the next calls to one endpoint answer with f instead of the real
// answer. Use Any for every endpoint, Failure.Once or Failure.NTimes to limit
// how long it lasts, and Clear to stop it early.
func (s *Stub) Fail(endpoint string, f Failure) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failures[endpoint] = &f
}

// Clear removes a forced failure.
func (s *Stub) Clear(endpoint string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.failures, endpoint)
}

// Requests returns every call the stub received, in order.
func (s *Stub) Requests() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Request, len(s.requests))
	copy(out, s.requests)
	return out
}

// Count returns how many calls one endpoint received. Any counts them all.
func (s *Stub) Count(endpoint string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, r := range s.requests {
		if endpoint == Any || r.Endpoint == endpoint {
			n++
		}
	}
	return n
}

// Events returns every event posted, in the order it arrived.
func (s *Stub) Events() []panel.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]panel.Event, len(s.events))
	copy(out, s.events)
	return out
}

// RawEvents returns the same events as they came off the wire, for assertions
// about which fields were sent at all.
func (s *Stub) RawEvents() []json.RawMessage {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]json.RawMessage, len(s.rawEvents))
	copy(out, s.rawEvents)
	return out
}

// Stats returns every aggregate posted, in the order it arrived.
func (s *Stub) Stats() []panel.Stat {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]panel.Stat, len(s.stats))
	copy(out, s.stats)
	return out
}

// RawStats returns the aggregates as they came off the wire, for assertions
// about null versus zero.
func (s *Stub) RawStats() []json.RawMessage {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]json.RawMessage, len(s.rawStats))
	copy(out, s.rawStats)
	return out
}

// EnsureSnapshots returns the registry snapshot of every POST /probe/ensure,
// in order.
func (s *Stub) EnsureSnapshots() [][]panel.MonClientSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([][]panel.MonClientSnapshot, len(s.ensures))
	copy(out, s.ensures)
	return out
}

// ProbeDeleted reports whether DELETE /probe has been called.
func (s *Stub) ProbeDeleted() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.probeDeleted
}

// Reset forgets every recorded request and forced failure, keeping the token
// and the state.
func (s *Stub) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests = nil
	s.events = nil
	s.rawEvents = nil
	s.stats = nil
	s.rawStats = nil
	s.ensures = nil
	s.seenEventIDs = map[string]bool{}
	s.failures = map[string]*Failure{}
}

// handle is the whole panel: authenticate, apply a forced failure, dispatch.
func (s *Stub) handle(w http.ResponseWriter, r *http.Request) {
	endpoint := endpointOf(r.URL.Path)
	body, tooLarge := readBody(r)
	s.record(Request{
		Method:   r.Method,
		Path:     r.URL.Path,
		Endpoint: endpoint,
		Query:    r.URL.Query(),
		Header:   r.Header.Clone(),
		Body:     body,
	})

	if !s.authorized(r) || endpoint == "" {
		bareNotFound(w)
		return
	}
	if f, ok := s.takeFailure(endpoint); ok {
		s.serveFailure(w, r, f)
		return
	}
	if tooLarge {
		s.writeError(w, http.StatusRequestEntityTooLarge, panel.CodeBatchTooLarge, "body is over 1 MiB")
		return
	}

	switch {
	case endpoint == State && r.Method == http.MethodGet:
		s.serveState(w)
	case endpoint == ProbeEnsure && r.Method == http.MethodPost:
		s.serveProbeEnsure(w, body)
	case endpoint == ProbeConfigs && r.Method == http.MethodGet:
		s.serveProbeConfigs(w, r.URL.Query().Get("host"))
	case endpoint == Probe && r.Method == http.MethodDelete:
		s.serveDeleteProbe(w)
	case endpoint == Events && r.Method == http.MethodPost:
		s.serveEvents(w, body)
	case endpoint == Stats && r.Method == http.MethodPost:
		s.serveStats(w, body)
	default:
		bareNotFound(w)
	}
}

func (s *Stub) serveState(w http.ResponseWriter) {
	s.mu.Lock()
	state := s.state
	s.mu.Unlock()
	s.writeJSON(w, http.StatusOK, state)
}

func (s *Stub) serveProbeEnsure(w http.ResponseWriter, body []byte) {
	var req struct {
		MonClients []panel.MonClientSnapshot `json:"monClients"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, panel.CodeInvalidBody, err.Error())
		return
	}
	if len(req.MonClients) > panel.MaxMonClients {
		s.writeError(w, http.StatusRequestEntityTooLarge, panel.CodeBatchTooLarge,
			fmt.Sprintf("monClients: %d over %d", len(req.MonClients), panel.MaxMonClients))
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensures = append(s.ensures, req.MonClients)
	created := []panel.ProbeRef{}
	if !s.ensured {
		s.ensured = true
		if s.state.Probe.SubID == nil {
			s.state.Probe.SubID = panel.StringPtr("k3j9d8s7f6g5h4j3")
		}
		for _, in := range s.state.Inbounds {
			created = append(created, panel.ProbeRef{Kind: in.Kind, InboundID: in.InboundID})
		}
	}
	now := clock.MS(s.clk.Now())
	s.state.Probe.LastEnsured = now
	s.probeDeleted = false
	s.writeJSONLocked(w, http.StatusOK, panel.ProbeEnsureResult{
		SubID:       s.state.Probe.SubIDValue(),
		Revision:    s.state.Revision,
		LastEnsured: now,
		Created:     created,
		Present:     len(s.state.Inbounds),
	})
}

func (s *Stub) serveProbeConfigs(w http.ResponseWriter, host string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.Probe.SubID == nil {
		s.writeErrorLocked(w, http.StatusConflict, panel.CodeProbeNotEnsured, "probe set is not ensured")
		return
	}
	path := panel.PathDirect
	if host == "" {
		if !s.state.Override.Enabled {
			s.writeErrorLocked(w, http.StatusConflict, panel.CodeOverrideDisabled, "host override is disabled")
			return
		}
		path = panel.PathProxy
		host = s.state.Override.Host
	}
	if pinned, ok := s.configs[path]; ok {
		s.writeJSONLocked(w, http.StatusOK, pinned)
		return
	}
	s.writeJSONLocked(w, http.StatusOK, s.renderConfigsLocked(path, host))
}

// renderConfigsLocked builds the probe material for the enabled inbounds, the
// way the panel renders a subscription for one path.
func (s *Stub) renderConfigsLocked(path, host string) panel.ProbeConfigs {
	out := panel.ProbeConfigs{Revision: s.state.Revision, Path: path, Items: []panel.ConfigItem{}}
	subID := s.state.Probe.SubIDValue()
	for _, in := range s.state.Inbounds {
		if !in.Enable {
			continue
		}
		switch in.Kind {
		case panel.InboundKindAWG:
			out.Items = append(out.Items, panel.ConfigItem{
				Kind:      in.Kind,
				InboundID: in.InboundID,
				Filename:  "probe-awg",
				Conf: fmt.Sprintf("[Interface]\nPrivateKey = %s\n[Peer]\nEndpoint = %s:%d\n",
					subID, host, in.Port),
			})
		default:
			out.Items = append(out.Items, panel.ConfigItem{
				Kind:      in.Kind,
				InboundID: in.InboundID,
				Link: fmt.Sprintf("%s://%s@%s:%d?security=reality#probe-%d",
					in.Protocol, subID, host, in.Port, in.InboundID),
			})
		}
	}
	return out
}

func (s *Stub) serveDeleteProbe(w http.ResponseWriter) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.Probe = panel.ProbeState{}
	s.ensured = false
	s.probeDeleted = true
	s.setContractHeaderLocked(w)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Stub) serveEvents(w http.ResponseWriter, body []byte) {
	var req struct {
		Events []json.RawMessage `json:"events"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, panel.CodeInvalidBody, err.Error())
		return
	}
	if len(req.Events) > panel.MaxEvents {
		s.writeError(w, http.StatusRequestEntityTooLarge, panel.CodeBatchTooLarge,
			fmt.Sprintf("events: %d over %d", len(req.Events), panel.MaxEvents))
		return
	}

	parsed := make([]panel.Event, len(req.Events))
	for i, raw := range req.Events {
		var event panel.Event
		if err := json.Unmarshal(raw, &event); err != nil {
			s.writeError(w, http.StatusBadRequest, panel.CodeInvalidBody,
				fmt.Sprintf("events[%d]: %v", i, err))
			return
		}
		if err := validateEvent(raw, event); err != nil {
			s.writeError(w, http.StatusBadRequest, panel.CodeInvalidBody,
				fmt.Sprintf("events[%d]: %v", i, err))
			return
		}
		parsed[i] = event
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	result := panel.EventsResult{Ignored: []panel.IgnoredEvent{}}
	for i, event := range parsed {
		s.events = append(s.events, event)
		s.rawEvents = append(s.rawEvents, req.Events[i])
		switch {
		case s.seenEventIDs[event.ID]:
			result.Duplicates++
		case event.Kind == panel.EventKindTarget && !s.knownInboundLocked(event.InboundKind, deref(event.InboundID)):
			result.Ignored = append(result.Ignored,
				panel.IgnoredEvent{ID: event.ID, Error: panel.CodeUnknownInbound})
		default:
			s.seenEventIDs[event.ID] = true
			result.Accepted++
		}
	}
	s.writeJSONLocked(w, http.StatusOK, result)
}

func (s *Stub) serveStats(w http.ResponseWriter, body []byte) {
	var req struct {
		Stats []json.RawMessage `json:"stats"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, panel.CodeInvalidBody, err.Error())
		return
	}
	if len(req.Stats) > panel.MaxStats {
		s.writeError(w, http.StatusRequestEntityTooLarge, panel.CodeBatchTooLarge,
			fmt.Sprintf("stats: %d over %d", len(req.Stats), panel.MaxStats))
		return
	}

	parsed := make([]panel.Stat, len(req.Stats))
	for i, raw := range req.Stats {
		var stat panel.Stat
		if err := json.Unmarshal(raw, &stat); err != nil {
			s.writeError(w, http.StatusBadRequest, panel.CodeInvalidBody,
				fmt.Sprintf("stats[%d]: %v", i, err))
			return
		}
		if err := validateStat(stat); err != nil {
			s.writeError(w, http.StatusBadRequest, panel.CodeInvalidBody,
				fmt.Sprintf("stats[%d]: %v", i, err))
			return
		}
		parsed[i] = stat
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	result := panel.StatsResult{Ignored: []panel.IgnoredStat{}}
	for i, stat := range parsed {
		s.stats = append(s.stats, stat)
		s.rawStats = append(s.rawStats, req.Stats[i])
		if !s.knownInboundLocked(stat.InboundKind, stat.InboundID) {
			result.Ignored = append(result.Ignored, panel.IgnoredStat{
				MonClientID: stat.MonClientID,
				InboundKind: stat.InboundKind,
				InboundID:   panel.Int64Ptr(stat.InboundID),
				Path:        stat.Path,
				BucketStart: stat.BucketStart,
				Error:       panel.CodeUnknownInbound,
			})
			continue
		}
		result.Accepted++
	}
	s.writeJSONLocked(w, http.StatusOK, result)
}

// knownInboundLocked reports whether the state lists this inbound. With strict
// inbounds off every inbound is known.
func (s *Stub) knownInboundLocked(kind string, id int64) bool {
	if !s.strictInbounds {
		return true
	}
	for _, in := range s.state.Inbounds {
		if in.Kind == kind && in.InboundID == id {
			return true
		}
	}
	return false
}

// validateEvent enforces the per-kind shape of contract §4.6: the fields a
// kind does not carry must be absent from the wire, not present and zero.
func validateEvent(raw json.RawMessage, event panel.Event) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	if event.ID == "" {
		return fmt.Errorf("id is required")
	}
	if event.TS == 0 {
		return fmt.Errorf("ts is required")
	}
	present := func(name string) bool { _, ok := fields[name]; return ok }
	forbid := func(names ...string) error {
		for _, name := range names {
			if present(name) {
				return fmt.Errorf("%s: not allowed for kind %q", name, event.Kind)
			}
		}
		return nil
	}
	require := func(names ...string) error {
		for _, name := range names {
			if !present(name) {
				return fmt.Errorf("%s: required for kind %q", name, event.Kind)
			}
		}
		return nil
	}
	switch event.Kind {
	case panel.EventKindTarget:
		return require("monClientId", "inboundKind", "inboundId", "path")
	case panel.EventKindMonClient:
		if err := require("monClientId"); err != nil {
			return err
		}
		return forbid("inboundKind", "inboundId", "path")
	case panel.EventKindPanel:
		return forbid("monClientId", "inboundKind", "inboundId", "path")
	default:
		return fmt.Errorf("kind: unknown value %q", event.Kind)
	}
}

// validateStat enforces the aggregate rules of contract §4.7: a five-minute
// bucket boundary, and null latencies when nothing succeeded.
func validateStat(stat panel.Stat) error {
	if stat.MonClientID == "" || stat.InboundKind == "" || stat.Path == "" {
		return fmt.Errorf("monClientId, inboundKind and path are required")
	}
	if stat.BucketStart == 0 || stat.BucketStart%300000 != 0 {
		return fmt.Errorf("bucketStart: %d is not a multiple of 300000", stat.BucketStart)
	}
	if stat.NOk == 0 {
		if stat.LatencyMinMS != nil || stat.LatencyAvgMS != nil || stat.LatencyMaxMS != nil {
			return fmt.Errorf("latency must be null when nOk is 0")
		}
	}
	return nil
}

// takeFailure returns the failure standing for this endpoint, counting it off
// when it was limited to a number of calls.
func (s *Stub) takeFailure(endpoint string) (Failure, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, key := range []string{endpoint, Any} {
		f, ok := s.failures[key]
		if !ok {
			continue
		}
		if f.Times > 0 {
			f.Times--
			if f.Times == 0 {
				delete(s.failures, key)
			}
		}
		return *f, true
	}
	return Failure{}, false
}

func (s *Stub) serveFailure(w http.ResponseWriter, r *http.Request, f Failure) {
	if f.Hang {
		select {
		case <-r.Context().Done():
		case <-s.done:
		}
		return
	}
	if f.Body != "" {
		s.setContractHeader(w)
		w.Header().Set("Content-Type", panel.ContentTypeJSON)
		w.WriteHeader(f.Status)
		_, _ = io.WriteString(w, f.Body)
		return
	}
	if f.Code == "" {
		w.WriteHeader(f.Status)
		return
	}
	s.writeError(w, f.Status, f.Code, f.Message)
}

func (s *Stub) authorized(r *http.Request) bool {
	s.mu.Lock()
	token := s.token
	s.mu.Unlock()
	const prefix = "Bearer "
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, prefix) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(header[len(prefix):]), []byte(token)) == 1
}

func (s *Stub) record(req Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests = append(s.requests, req)
}

func (s *Stub) writeJSON(w http.ResponseWriter, status int, payload any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.writeJSONLocked(w, status, payload)
}

func (s *Stub) writeJSONLocked(w http.ResponseWriter, status int, payload any) {
	s.setContractHeaderLocked(w)
	w.Header().Set("Content-Type", panel.ContentTypeJSON)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func (s *Stub) writeError(w http.ResponseWriter, status int, code, message string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.writeErrorLocked(w, status, code, message)
}

func (s *Stub) writeErrorLocked(w http.ResponseWriter, status int, code, message string) {
	s.writeJSONLocked(w, status, map[string]string{"error": code, "message": message})
}

func (s *Stub) setContractHeader(w http.ResponseWriter) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.setContractHeaderLocked(w)
}

func (s *Stub) setContractHeaderLocked(w http.ResponseWriter) {
	if s.contractHeader != "" {
		w.Header().Set(panel.HeaderContract, s.contractHeader)
	}
}

// bareNotFound is the answer of contract §2: no body, nothing to tell an
// unauthenticated caller that monitoring is even here.
func bareNotFound(w http.ResponseWriter) { w.WriteHeader(http.StatusNotFound) }

// endpointOf strips whatever webBasePath the panel is served under and returns
// the contract endpoint, or the empty string when the path is not one.
func endpointOf(path string) string {
	const marker = "/mon/v1/"
	i := strings.Index(path, marker)
	if i < 0 {
		return ""
	}
	endpoint := strings.Trim(path[i+len(marker):], "/")
	switch endpoint {
	case State, ProbeEnsure, ProbeConfigs, Probe, Events, Stats:
		return endpoint
	default:
		return ""
	}
}

// readBody reads at most one byte over the panel's limit, so that an oversized
// body can be answered with 413 rather than buffered.
func readBody(r *http.Request) (body []byte, tooLarge bool) {
	if r.Body == nil {
		return nil, false
	}
	body, _ = io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
	if len(body) > maxBodyBytes {
		return body[:maxBodyBytes], true
	}
	return body, false
}

// deref reads a nullable inbound id, treating absence as the AWG server's 0.
func deref(v *int64) int64 {
	if v == nil {
		return 0
	}
	return *v
}
