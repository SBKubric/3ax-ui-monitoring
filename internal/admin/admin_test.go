package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
)

// The credentials every test logs in with.
const (
	testUser     = "operator"
	testPassword = "correct horse battery staple"
	testIP       = "203.0.113.5"
	otherIP      = "198.51.100.9"
)

// testTime is the fixed instant the fake clock starts at.
var testTime = time.Date(2025, 9, 16, 12, 0, 0, 0, time.UTC)

// fakeRegistry records what the handlers asked the registry to do, which is
// how the tests assert that the form's arguments reach it unchanged.
type fakeRegistry struct {
	mu sync.Mutex

	pending  []PendingRequest
	clients  []Client
	approved Client
	err      error

	approvals []Approval
	rejects   []string
	edits     []editCall
	switches  []switchCall
	revokes   []string
	deletes   []string
}

type editCall struct {
	ID   string
	Edit ClientEdit
}

type switchCall struct {
	ID      string
	Enabled bool
}

func (f *fakeRegistry) PendingRequests(context.Context) ([]PendingRequest, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.pending, f.err
}

func (f *fakeRegistry) PendingCount(context.Context) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.pending), f.err
}

func (f *fakeRegistry) Approve(_ context.Context, a Approval) (Client, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.approvals = append(f.approvals, a)
	if f.err != nil {
		return Client{}, f.err
	}
	if f.approved.ID != "" {
		return f.approved, nil
	}
	return Client{ID: "approved", Name: a.Name, Region: a.Region, Paths: a.Paths}, nil
}

func (f *fakeRegistry) Reject(_ context.Context, requestID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rejects = append(f.rejects, requestID)
	return f.err
}

func (f *fakeRegistry) Clients(context.Context) ([]Client, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.clients, f.err
}

func (f *fakeRegistry) UpdateClient(_ context.Context, id string, e ClientEdit) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.edits = append(f.edits, editCall{ID: id, Edit: e})
	return f.err
}

func (f *fakeRegistry) SetClientEnabled(_ context.Context, id string, enabled bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.switches = append(f.switches, switchCall{ID: id, Enabled: enabled})
	return f.err
}

func (f *fakeRegistry) RevokeClient(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revokes = append(f.revokes, id)
	return f.err
}

func (f *fakeRegistry) DeleteClient(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deletes = append(f.deletes, id)
	return f.err
}

// fakePanel records the Check calls.
type fakePanel struct {
	mu     sync.Mutex
	calls  []panelCall
	result PanelCheck
	err    error
}

type panelCall struct {
	URL   string
	Token string
}

func (f *fakePanel) CheckPanel(_ context.Context, panelURL, monToken string) (PanelCheck, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, panelCall{URL: panelURL, Token: monToken})
	return f.result, f.err
}

// fakeTelegram records the Send test calls.
type fakeTelegram struct {
	mu    sync.Mutex
	calls []telegramCall
	err   error
}

type telegramCall struct {
	Token  string
	ChatID string
}

func (f *fakeTelegram) SendTestMessage(_ context.Context, tgToken, tgChatID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, telegramCall{Token: tgToken, ChatID: tgChatID})
	return f.err
}

// fakeRebuilder counts the configuration rebuilds a Save triggered.
type fakeRebuilder struct {
	mu    sync.Mutex
	calls int
	err   error
}

func (f *fakeRebuilder) RebuildAll(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.err
}

func (f *fakeRebuilder) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// harness is one admin UI wired to a real store in a temporary directory, a
// fake clock and fakes for the four injected services.
type harness struct {
	t        *testing.T
	server   *Server
	handler  http.Handler
	store    *store.Store
	clock    *clock.Fake
	registry *fakeRegistry
	panel    *fakePanel
	telegram *fakeTelegram
	configs  *fakeRebuilder
}

// newHarness builds the admin UI with an administrator already set.
func newHarness(t *testing.T, opts ...func(*Options)) *harness {
	t.Helper()
	clk := clock.NewFake(testTime)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	st, err := store.Open(filepath.Join(t.TempDir(), "mon-server.db"), logger, store.WithClock(clk))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.SetAdmin(testUser, testPassword); err != nil {
		t.Fatalf("set admin: %v", err)
	}

	h := &harness{
		t:        t,
		store:    st,
		clock:    clk,
		registry: &fakeRegistry{},
		panel:    &fakePanel{},
		telegram: &fakeTelegram{},
		configs:  &fakeRebuilder{},
	}
	options := Options{
		Store:    st,
		Registry: h.registry,
		Panel:    h.panel,
		Telegram: h.telegram,
		Configs:  h.configs,
		Clock:    clk,
		Log:      logger,
		Server: ServerInfo{
			PublicIP: "192.0.2.10",
			Version:  "test",
			TLSMode:  "acme-ip",
			Listen:   ":443",
			DataDir:  "/var/lib/mon-server",
		},
	}
	for _, opt := range opts {
		opt(&options)
	}
	srv, err := New(options)
	if err != nil {
		t.Fatalf("new admin server: %v", err)
	}
	h.server = srv
	h.handler = srv.Handler()
	return h
}

// request builds one request from ip with an optional JSON body.
func (h *harness) request(method, path string, body any, ip string, cookies ...*http.Cookie) *http.Request {
	h.t.Helper()
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			h.t.Fatalf("marshal body: %v", err)
		}
		reader = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, path, reader)
	req.RemoteAddr = ip + ":51234"
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for _, c := range cookies {
		if c != nil {
			req.AddCookie(c)
		}
	}
	return req
}

// do runs one request through the mux.
func (h *harness) do(req *http.Request) *httptest.ResponseRecorder {
	h.t.Helper()
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)
	return rec
}

// post is the shorthand every mutation test uses.
func (h *harness) post(path string, body any, cookie *http.Cookie) *httptest.ResponseRecorder {
	h.t.Helper()
	return h.do(h.request(http.MethodPost, path, body, testIP, cookie))
}

// get is the shorthand for a read.
func (h *harness) get(path string, cookie *http.Cookie) *httptest.ResponseRecorder {
	h.t.Helper()
	return h.do(h.request(http.MethodGet, path, nil, testIP, cookie))
}

// loginFrom signs in from ip and returns the response.
func (h *harness) loginFrom(ip, username, password string) *httptest.ResponseRecorder {
	h.t.Helper()
	body := map[string]string{"username": username, "password": password}
	return h.do(h.request(http.MethodPost, "/admin/api/login", body, ip))
}

// signInWithPassword goes through the login endpoint and returns the session
// cookie it set. The login tests use it; everything else takes the cheaper
// signIn, because bcrypt under -race costs seconds per call.
func (h *harness) signInWithPassword() *http.Cookie {
	h.t.Helper()
	rec := h.loginFrom(testIP, testUser, testPassword)
	if rec.Code != http.StatusOK {
		h.t.Fatalf("login: got %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	cookie := sessionCookie(h.t, rec)
	if cookie == nil {
		h.t.Fatal("login did not set the session cookie")
	}
	return cookie
}

// signIn issues a session the way a successful login does, without paying for
// bcrypt. What the login itself does is covered by the login tests.
func (h *harness) signIn() *http.Cookie {
	h.t.Helper()
	id, expires, err := h.server.issueSession(testIP)
	if err != nil {
		h.t.Fatalf("issue session: %v", err)
	}
	return &http.Cookie{Name: SessionCookie, Value: id, Expires: expires}
}

// sessionCookie picks the session cookie out of a response.
func sessionCookie(t *testing.T, rec *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == SessionCookie {
			return c
		}
	}
	return nil
}

// decode reads the response envelope.
func decode(t *testing.T, rec *httptest.ResponseRecorder) Envelope {
	t.Helper()
	var env Envelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode envelope from %q: %v", rec.Body.String(), err)
	}
	return env
}

// decodeObj reads the obj of the envelope into dst and insists on success.
func decodeObj(t *testing.T, rec *httptest.ResponseRecorder, dst any) {
	t.Helper()
	var raw struct {
		Success bool            `json:"success"`
		Msg     string          `json:"msg"`
		Obj     json.RawMessage `json:"obj"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	if !raw.Success {
		t.Fatalf("envelope reports failure: %s", raw.Msg)
	}
	if err := json.Unmarshal(raw.Obj, dst); err != nil {
		t.Fatalf("decode obj %s: %v", raw.Obj, err)
	}
}

// unmarshalObj reads the obj of an envelope whatever the status was, which is
// how the login tests look at a refusal.
func unmarshalObj(rec *httptest.ResponseRecorder, dst any) error {
	var raw struct {
		Obj json.RawMessage `json:"obj"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		return err
	}
	if len(raw.Obj) == 0 || string(raw.Obj) == "null" {
		return errors.New("the envelope carries no obj")
	}
	return json.Unmarshal(raw.Obj, dst)
}

// TestNewRejectsMissingDependencies keeps the two required services required.
func TestNewRejectsMissingDependencies(t *testing.T) {
	t.Parallel()
	if _, err := New(Options{Registry: &fakeRegistry{}}); err == nil {
		t.Fatal("a server without a store was accepted")
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	st, err := store.Open(filepath.Join(t.TempDir(), "mon-server.db"), logger)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if _, err := New(Options{Store: st}); err == nil {
		t.Fatal("a server without a registry was accepted")
	}
}

// TestDefaultsAreFilledIn covers the defaults New puts in place.
func TestDefaultsAreFilledIn(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	if h.server.info.AdminHint != DefaultAdminHint {
		t.Errorf("admin hint = %q, want %q", h.server.info.AdminHint, DefaultAdminHint)
	}
	if h.server.limits != DefaultRateLimits() {
		t.Errorf("rate limits = %+v, want %+v", h.server.limits, DefaultRateLimits())
	}
}

// errFake stands in for a failure inside an injected service.
var errFake = errors.New("fake service failure")
