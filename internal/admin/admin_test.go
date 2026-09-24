package admin

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/api"
	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
	"github.com/SBKubric/3ax-ui-monitoring/internal/config"
	"github.com/SBKubric/3ax-ui-monitoring/internal/panel"
	"github.com/SBKubric/3ax-ui-monitoring/internal/registry"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
)

// Test credentials for the single admin account (spec §2: `mon-server admin
// set <user>`).
const (
	testUser = "admin"
	testPass = "correct horse battery staple"
	testIP   = "192.0.2.1"
)

// fakeMaterial stands in for the panel poll loop: it satisfies both
// registry.MaterialSource (so the config builder can build documents) and
// admin.PanelStatus (so the Settings page has a status line), without a poll
// cycle or a network.
type fakeMaterial struct {
	mat       panel.Material
	have      bool
	down      bool
	untrusted bool
	contract  string

	// refreshes counts RefreshMaterial calls; refreshErr is what they
	// answer.
	refreshes  int
	refreshErr error
}

func (f *fakeMaterial) RefreshMaterial(context.Context) error {
	f.refreshes++
	return f.refreshErr
}

func (f *fakeMaterial) Material() (panel.Material, bool) { return f.mat, f.have }
func (f *fakeMaterial) PanelDown() bool                  { return f.down }
func (f *fakeMaterial) UnknownAuthority() bool           { return f.untrusted }
func (f *fakeMaterial) ContractError() string            { return f.contract }

// fakeTelegram records what "Send test" sent, standing in for tg.HTTP where a
// test does not need a real Bot API round trip.
type fakeTelegram struct {
	token, chat, text string
	err               error
}

func (f *fakeTelegram) SendTo(_ context.Context, token, chatID, text string) error {
	f.token, f.chat, f.text = token, chatID, text
	return f.err
}

// harness is one fully mounted admin UI over a temp-file store, a Fake clock
// and a fake panel — everything a handler test needs and nothing it does not.
type harness struct {
	t       *testing.T
	st      *store.Store
	clk     *clock.Fake
	reg     *registry.Registry
	configs *registry.ConfigBuilder
	mat     *fakeMaterial
	tg      *fakeTelegram
	handler *Handler
	srv     *api.Server

	// cookie is the session cookie login() captured, replayed on every
	// later request the way a browser would.
	cookie string
	// panelClients records every (url, token) pair the Check button built a
	// client for, so a test can prove it used the submitted values.
	panelClients []string
	newPanel     func(url, token string, rootCAs *x509.CertPool) panel.Client
}

func newHarness(t *testing.T) *harness {
	t.Helper()

	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	clk := clock.NewFake(time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC))
	st.Clock = clk
	if err := st.SetAdmin(testUser, testPass); err != nil {
		t.Fatalf("SetAdmin: %v", err)
	}

	mat := &fakeMaterial{}
	reg := registry.New(st, clk)
	configs := registry.NewConfigBuilder(st, clk, mat, "https://192.0.2.44:443/v1/probe")
	reg.SetHooks(registry.Hooks{PathsChanged: configs.Rebuild, Approved: configs.Rebuild})

	h := &harness{
		t: t, st: st, clk: clk, reg: reg, configs: configs, mat: mat,
		tg: &fakeTelegram{},
	}
	h.handler = New(Deps{
		Store:    st,
		Clock:    clk,
		Registry: reg,
		Configs:  configs,
		Poller:   mat,
		Cfg:      &config.Config{Listen: ":443", PublicIP: "192.0.2.44", DataDir: t.TempDir(), TLS: config.TLSConfig{Mode: config.TLSModeACMEIP}},
		Telegram: h.tg,
		NewPanelClient: func(url, token string, rootCAs *x509.CertPool) panel.Client {
			h.panelClients = append(h.panelClients, url+"|"+token)
			if h.newPanel != nil {
				return h.newPanel(url, token, rootCAs)
			}
			return panel.NewHTTPClient(url, token, clk, panel.WithRootCAs(rootCAs))
		},
	})
	h.srv = api.New()
	h.handler.Mount(h.srv.Admin)
	return h
}

// do issues one request through the whole gin engine, as a browser would:
// the session cookie when there is one, the CSRF header unless the test is
// specifically checking its absence.
func (h *harness) do(method, path string, body any, opts ...func(*http.Request)) *httptest.ResponseRecorder {
	h.t.Helper()

	var r *http.Request
	if body == nil {
		r = httptest.NewRequest(method, path, nil)
	} else {
		raw, err := json.Marshal(body)
		if err != nil {
			h.t.Fatalf("marshal body: %v", err)
		}
		r = httptest.NewRequest(method, path, bytes.NewReader(raw))
		r.Header.Set("Content-Type", "application/json")
	}
	r.RemoteAddr = testIP + ":54321"
	r.Header.Set(xhrHeader, xhrValue)
	if h.cookie != "" {
		r.Header.Set("Cookie", SessionCookie+"="+h.cookie)
	}
	for _, o := range opts {
		o(r)
	}

	w := httptest.NewRecorder()
	h.srv.Engine.ServeHTTP(w, r)
	return w
}

// noXHR drops the CSRF header from one request.
func noXHR(r *http.Request) { r.Header.Del(xhrHeader) }

// noCookie drops the session cookie from one request.
func noCookie(r *http.Request) { r.Header.Del("Cookie") }

// fromIP overrides the source IP, for the per-IP lockout tests.
func fromIP(ip string) func(*http.Request) {
	return func(r *http.Request) { r.RemoteAddr = ip + ":54321" }
}

// login signs in with the test credentials and keeps the cookie.
func (h *harness) login() {
	h.t.Helper()
	w := h.do(http.MethodPost, "/admin/login", map[string]any{"username": testUser, "password": testPass})
	if w.Code != http.StatusOK {
		h.t.Fatalf("login: status %d, body %s", w.Code, w.Body.String())
	}
	h.cookie = sessionCookieOf(h.t, w)
	if h.cookie == "" {
		h.t.Fatal("login set no session cookie")
	}
}

// sessionCookieOf digs the session cookie's value out of a response.
func sessionCookieOf(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	for _, c := range w.Result().Cookies() {
		if c.Name == SessionCookie {
			return c.Value
		}
	}
	return ""
}

// decode reads the admin envelope out of a response.
func decode(t *testing.T, w *httptest.ResponseRecorder) envelope {
	t.Helper()
	var env envelope
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode envelope from %q: %v", w.Body.String(), err)
	}
	return env
}

// obj reads the envelope's obj as a map.
func obj(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var wrapper struct {
		Obj map[string]any `json:"obj"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &wrapper); err != nil {
		t.Fatalf("decode obj from %q: %v", w.Body.String(), err)
	}
	return wrapper.Obj
}

// ---------------------------------------------------------------------
// Sessions and the login lockout (spec §9.1)
// ---------------------------------------------------------------------

// TestLogin_IssuesSessionCookie: the happy path, and the cookie carries the
// attributes spec §9.1 fixes.
func TestLogin_IssuesSessionCookie(t *testing.T) {
	h := newHarness(t)

	w := h.do(http.MethodPost, "/admin/login", map[string]any{"username": testUser, "password": testPass})
	if w.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", w.Code, w.Body.String())
	}

	var cookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == SessionCookie {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("no mon_session cookie")
	}
	if !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("cookie attributes: HttpOnly=%v Secure=%v SameSite=%v, want true/true/Lax", cookie.HttpOnly, cookie.Secure, cookie.SameSite)
	}
	if cookie.Path != "/admin" {
		t.Fatalf("cookie path = %q, want /admin", cookie.Path)
	}
	if want := int(store.SessionTTL.Seconds()); cookie.MaxAge != want {
		t.Fatalf("cookie MaxAge = %d, want %d (24 h)", cookie.MaxAge, want)
	}
}

// TestLogin_WrongPasswordLocksAfterFive walks spec §9.1's guard through the
// HTTP layer, including the lock lapsing after fifteen minutes.
func TestLogin_WrongPasswordLocksAfterFive(t *testing.T) {
	h := newHarness(t)
	bad := map[string]any{"username": testUser, "password": "nope"}

	for i := 1; i < store.MaxLoginFailures; i++ {
		w := h.do(http.MethodPost, "/admin/login", bad)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("failure %d: status %d, want 401", i, w.Code)
		}
	}

	w := h.do(http.MethodPost, "/admin/login", bad)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("fifth failure: status %d, want 429", w.Code)
	}

	// Even the right password is refused while the IP is locked.
	w = h.do(http.MethodPost, "/admin/login", map[string]any{"username": testUser, "password": testPass})
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("correct password while locked: status %d, want 429", w.Code)
	}
	// ... but not from another IP.
	w = h.do(http.MethodPost, "/admin/login", map[string]any{"username": testUser, "password": testPass}, fromIP("198.51.100.9"))
	if w.Code != http.StatusOK {
		t.Fatalf("another IP while the first is locked: status %d, want 200", w.Code)
	}

	h.clk.Advance(store.LoginLockout + time.Second)
	w = h.do(http.MethodPost, "/admin/login", map[string]any{"username": testUser, "password": testPass})
	if w.Code != http.StatusOK {
		t.Fatalf("after the lockout lapsed: status %d, body %s", w.Code, w.Body.String())
	}
}

// TestLogin_SuccessClearsTheStreak: four failures then a success, then four
// more failures must not add up to a lock (spec §9.1: five *in a row*).
func TestLogin_SuccessClearsTheStreak(t *testing.T) {
	h := newHarness(t)
	bad := map[string]any{"username": testUser, "password": "nope"}

	for range store.MaxLoginFailures - 1 {
		h.do(http.MethodPost, "/admin/login", bad)
	}
	h.login()

	for i := range store.MaxLoginFailures - 1 {
		if w := h.do(http.MethodPost, "/admin/login", bad); w.Code != http.StatusUnauthorized {
			t.Fatalf("failure %d after a success: status %d, want 401", i+1, w.Code)
		}
	}
}

// TestLogout_InvalidatesTheSession: the cookie stops working the moment Log
// out returns.
func TestLogout_InvalidatesTheSession(t *testing.T) {
	h := newHarness(t)
	h.login()

	if w := h.do(http.MethodGet, "/admin/api/clients", nil); w.Code != http.StatusOK {
		t.Fatalf("before logout: status %d", w.Code)
	}
	if w := h.do(http.MethodPost, "/admin/logout", nil); w.Code != http.StatusOK {
		t.Fatalf("logout: status %d", w.Code)
	}
	if w := h.do(http.MethodGet, "/admin/api/clients", nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("after logout: status %d, want 401", w.Code)
	}
}

// TestSession_ExpiresAfter24h: spec §9.1's session lifetime, through HTTP.
func TestSession_ExpiresAfter24h(t *testing.T) {
	h := newHarness(t)
	h.login()

	h.clk.Advance(store.SessionTTL - time.Minute)
	if w := h.do(http.MethodGet, "/admin/api/clients", nil); w.Code != http.StatusOK {
		t.Fatalf("just before the TTL: status %d", w.Code)
	}

	h.clk.Advance(2 * time.Minute)
	if w := h.do(http.MethodGet, "/admin/api/clients", nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("after the TTL: status %d, want 401", w.Code)
	}
	if w := h.do(http.MethodGet, "/admin/requests", nil); w.Code != http.StatusFound {
		t.Fatalf("page after the TTL: status %d, want a 302 to the login form", w.Code)
	}
}

// TestNoSession_PagesRedirectApiIs401 is the issue's own wording: "/admin/*
// без сессии → редирект на логин, /admin/api/* → 401".
func TestNoSession_PagesRedirectApiIs401(t *testing.T) {
	h := newHarness(t)

	for _, path := range []string{"/admin/", "/admin/requests", "/admin/clients", "/admin/settings"} {
		w := h.do(http.MethodGet, path, nil, noCookie)
		if w.Code != http.StatusFound {
			t.Fatalf("%s: status %d, want 302", path, w.Code)
		}
		if loc := w.Header().Get("Location"); !strings.HasPrefix(loc, "/admin/login") {
			t.Fatalf("%s redirected to %q, want the login form", path, loc)
		}
	}

	for _, path := range []string{"/admin/api/requests", "/admin/api/clients", "/admin/api/settings"} {
		w := h.do(http.MethodGet, path, nil, noCookie)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("%s: status %d, want 401", path, w.Code)
		}
		if env := decode(t, w); env.Success {
			t.Fatalf("%s: success = true on a 401", path)
		}
	}
}

// TestNoSession_RedirectCarriesNext: a browser sent to the login form comes
// back to the page it was actually after.
func TestNoSession_RedirectCarriesNext(t *testing.T) {
	h := newHarness(t)
	w := h.do(http.MethodGet, "/admin/settings", nil, noCookie)
	if loc := w.Header().Get("Location"); !strings.Contains(loc, "next=%2Fadmin%2Fsettings") {
		t.Fatalf("Location = %q, want ?next=/admin/settings", loc)
	}
}

// TestCSRF_MissingHeaderIsRejected: a mutating call without the
// X-Requested-With header is refused even with a valid session (spec §9.1's
// SameSite=Lax cookie plus this header is the whole CSRF defence).
func TestCSRF_MissingHeaderIsRejected(t *testing.T) {
	h := newHarness(t)
	h.login()

	w := h.do(http.MethodPost, "/admin/api/settings", map[string]any{}, noXHR)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403", w.Code)
	}
	// Reads are exempt: they change nothing and the attacker cannot read
	// the answer anyway.
	if w := h.do(http.MethodGet, "/admin/api/settings", nil, noXHR); w.Code != http.StatusOK {
		t.Fatalf("GET without the header: status %d, want 200", w.Code)
	}
}

// ---------------------------------------------------------------------
// Pages and assets (spec §9.1)
// ---------------------------------------------------------------------

// TestPages_Render: every page renders, carrying the data-testid root the
// e2e harness selects by.
func TestPages_Render(t *testing.T) {
	h := newHarness(t)
	h.login()

	cases := []struct{ path, testid string }{
		{"/admin/login", `data-testid="login-page"`},
		{"/admin/requests", `data-testid="requests-page"`},
		{"/admin/clients", `data-testid="clients-page"`},
		{"/admin/settings", `data-testid="settings-page"`},
	}
	for _, tc := range cases {
		// The login page redirects a signed-in browser away, so ask for it
		// without the cookie.
		opts := []func(*http.Request){}
		if tc.path == "/admin/login" {
			opts = append(opts, noCookie)
		}
		w := h.do(http.MethodGet, tc.path, nil, opts...)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: status %d", tc.path, w.Code)
		}
		if !strings.Contains(w.Body.String(), tc.testid) {
			t.Fatalf("%s: body does not carry %s", tc.path, tc.testid)
		}
		if !strings.Contains(w.Body.String(), "/admin/assets/vue.global.prod.js") {
			t.Fatalf("%s: body does not load the embedded Vue bundle", tc.path)
		}
	}
}

// TestIndex_RedirectsToRequests: /admin lands on the Requests page.
func TestIndex_RedirectsToRequests(t *testing.T) {
	h := newHarness(t)
	h.login()
	w := h.do(http.MethodGet, "/admin/", nil)
	if w.Code != http.StatusFound || w.Header().Get("Location") != "/admin/requests" {
		t.Fatalf("status %d, Location %q; want 302 → /admin/requests", w.Code, w.Header().Get("Location"))
	}
}

// TestLoginPage_SignedInIsSentOn: an administrator who still has a session
// never sees the password field again.
func TestLoginPage_SignedInIsSentOn(t *testing.T) {
	h := newHarness(t)
	h.login()
	w := h.do(http.MethodGet, "/admin/login", nil)
	if w.Code != http.StatusFound {
		t.Fatalf("status %d, want 302", w.Code)
	}
}

// TestAssets_ServedFromTheEmbedWithCacheHeader: the UMD bundles come out of
// the binary, with the right media type and a cache header, and without a
// session (the login page needs them).
func TestAssets_ServedFromTheEmbedWithCacheHeader(t *testing.T) {
	h := newHarness(t)

	for _, name := range []string{"vue.global.prod.js", "antd.min.js", "antd.min.css", "dayjs.min.js", "app.js", "app.css", "page-login.js", "page-requests.js", "page-clients.js", "page-settings.js"} {
		w := h.do(http.MethodGet, "/admin/assets/"+name, nil, noCookie)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: status %d", name, w.Code)
		}
		if w.Body.Len() == 0 {
			t.Fatalf("%s: empty body", name)
		}
		if got := w.Header().Get("Cache-Control"); got != assetMaxAge {
			t.Fatalf("%s: Cache-Control = %q, want %q", name, got, assetMaxAge)
		}
		wantType := "application/javascript"
		if strings.HasSuffix(name, ".css") {
			wantType = "text/css"
		}
		if got := w.Header().Get("Content-Type"); !strings.HasPrefix(got, wantType) {
			t.Fatalf("%s: Content-Type = %q, want %s", name, got, wantType)
		}
	}

	if w := h.do(http.MethodGet, "/admin/assets/../html/layout.html", nil, noCookie); w.Code == http.StatusOK {
		t.Fatal("a path traversal out of web/assets was served")
	}
	if w := h.do(http.MethodGet, "/admin/assets/nope.js", nil, noCookie); w.Code != http.StatusNotFound {
		t.Fatalf("missing asset: status %d, want 404", w.Code)
	}
}
