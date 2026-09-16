package admin

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
)

// TestLoginIssuesSession covers the happy path: a correct login stores a
// session row and hands back the cookie.
func TestLoginIssuesSession(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	rec := h.loginFrom(testIP, testUser, testPassword)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	cookie := sessionCookie(t, rec)
	if cookie == nil {
		t.Fatal("no session cookie was set")
	}
	if len(cookie.Value) < 40 {
		t.Errorf("session id %q is shorter than 32 random bytes in base64url", cookie.Value)
	}

	var row store.AdminSession
	if err := h.store.DB().Where("id = ?", cookie.Value).Take(&row).Error; err != nil {
		t.Fatalf("session row: %v", err)
	}
	if row.IP != testIP {
		t.Errorf("session ip = %q, want %q", row.IP, testIP)
	}
	wantExpiry := clock.MS(testTime.Add(SessionTTL))
	if row.ExpiresAt != wantExpiry {
		t.Errorf("expires_at = %d, want %d (24 hours)", row.ExpiresAt, wantExpiry)
	}
	if row.CreatedAt != clock.MS(testTime) {
		t.Errorf("created_at = %d, want %d", row.CreatedAt, clock.MS(testTime))
	}
}

// TestLoginCookieAttributes pins the three cookie flags of §9.1.
func TestLoginCookieAttributes(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	rec := h.loginFrom(testIP, testUser, testPassword)
	cookie := sessionCookie(t, rec)
	if cookie == nil {
		t.Fatal("no session cookie was set")
	}
	if !cookie.HttpOnly {
		t.Error("the session cookie is not HttpOnly")
	}
	if !cookie.Secure {
		t.Error("the session cookie is not Secure")
	}
	if cookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite = %v, want Lax", cookie.SameSite)
	}
	raw := rec.Header().Get("Set-Cookie")
	for _, want := range []string{"HttpOnly", "Secure", "SameSite=Lax"} {
		if !strings.Contains(raw, want) {
			t.Errorf("Set-Cookie %q does not carry %s", raw, want)
		}
	}
}

// TestLoginWrongPasswordIsRefused checks that a wrong password issues nothing.
func TestLoginWrongPasswordIsRefused(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	rec := h.loginFrom(testIP, testUser, "not the password")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if c := sessionCookie(t, rec); c != nil {
		t.Fatalf("a session cookie was issued on a wrong password: %q", c.Value)
	}
	env := decode(t, rec)
	if env.Success {
		t.Error("the envelope reports success on a wrong password")
	}
	var count int64
	if err := h.store.DB().Model(&store.AdminSession{}).Count(&count).Error; err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	if count != 0 {
		t.Errorf("%d sessions were stored, want 0", count)
	}
}

// TestLoginWrongUsernameIsRefused: the username is checked too.
func TestLoginWrongUsernameIsRefused(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	rec := h.loginFrom(testIP, "someone-else", testPassword)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

// TestLockoutAfterFiveFailures is the rule of §9.1: five failures from one IP
// lock it for fifteen minutes, the sixth attempt is refused even with the
// right password, another IP is unaffected, and the window expiring lets the
// first one back in.
func TestLockoutAfterFiveFailures(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	for i := 1; i <= MaxLoginFailures-1; i++ {
		rec := h.loginFrom(testIP, testUser, "wrong")
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status = %d, want 401", i, rec.Code)
		}
	}
	// The fifth failure is the one that locks the address.
	rec := h.loginFrom(testIP, testUser, "wrong")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("fifth failure: status = %d, want 429 (%s)", rec.Code, rec.Body.String())
	}

	// The sixth attempt carries the right password and is still refused.
	rec = h.loginFrom(testIP, testUser, testPassword)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("sixth attempt with the right password: status = %d, want 429", rec.Code)
	}
	if c := sessionCookie(t, rec); c != nil {
		t.Fatal("a locked-out address was given a session")
	}

	// A different address is not affected by the lockout.
	rec = h.loginFrom(otherIP, testUser, testPassword)
	if rec.Code != http.StatusOK {
		t.Fatalf("other address: status = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}

	// Still locked one second before the window ends.
	h.clock.Advance(LockoutDuration - time.Second)
	rec = h.loginFrom(testIP, testUser, testPassword)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("just before the window ends: status = %d, want 429", rec.Code)
	}

	// And allowed in again once it has passed.
	h.clock.Advance(2 * time.Second)
	rec = h.loginFrom(testIP, testUser, testPassword)
	if rec.Code != http.StatusOK {
		t.Fatalf("after the lockout window: status = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	if sessionCookie(t, rec) == nil {
		t.Fatal("no session after the lockout window passed")
	}
}

// TestLockoutWindowStartsCountingAgain: after the window the counter is back
// at zero, so one failure does not lock the address straight away.
func TestLockoutWindowStartsCountingAgain(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	for i := 0; i < MaxLoginFailures; i++ {
		h.loginFrom(testIP, testUser, "wrong")
	}
	h.clock.Advance(LockoutDuration + time.Second)

	rec := h.loginFrom(testIP, testUser, "wrong")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("first failure after the window: status = %d, want 401 (a fresh count)", rec.Code)
	}
	var row store.LoginAttempt
	if err := h.store.DB().Where("ip = ?", testIP).Take(&row).Error; err != nil {
		t.Fatalf("login attempt row: %v", err)
	}
	if row.Failures != 1 {
		t.Errorf("failures = %d, want 1", row.Failures)
	}
	if row.LockedUntil != 0 {
		t.Errorf("locked_until = %d, want 0", row.LockedUntil)
	}
}

// TestSuccessfulLoginClearsTheCounter: the counter resets on success, so four
// failures and a success leave nothing behind.
func TestSuccessfulLoginClearsTheCounter(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	for i := 0; i < MaxLoginFailures-1; i++ {
		h.loginFrom(testIP, testUser, "wrong")
	}
	if rec := h.loginFrom(testIP, testUser, testPassword); rec.Code != http.StatusOK {
		t.Fatalf("login after four failures: status = %d, want 200", rec.Code)
	}

	var count int64
	if err := h.store.DB().Model(&store.LoginAttempt{}).Where("ip = ?", testIP).Count(&count).Error; err != nil {
		t.Fatalf("count login attempts: %v", err)
	}
	if count != 0 {
		t.Fatalf("%d login_attempts rows survived a successful login, want 0", count)
	}

	// Four more failures must therefore not lock the address.
	for i := 0; i < MaxLoginFailures-1; i++ {
		if rec := h.loginFrom(testIP, testUser, "wrong"); rec.Code != http.StatusUnauthorized {
			t.Fatalf("failure %d after the reset: status = %d, want 401", i+1, rec.Code)
		}
	}
}

// TestLoginReportsAttemptsLeft: the card counts down to the lockout.
func TestLoginReportsAttemptsLeft(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	rec := h.loginFrom(testIP, testUser, "wrong")
	var result loginResult
	if err := unmarshalObj(rec, &result); err != nil {
		t.Fatalf("decode obj: %v", err)
	}
	if result.AttemptsLeft != MaxLoginFailures-1 {
		t.Errorf("attemptsLeft = %d, want %d", result.AttemptsLeft, MaxLoginFailures-1)
	}
}

// TestExpiredSessionIsRefused: a session past its expiry is no session.
func TestExpiredSessionIsRefused(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	cookie := h.signIn()

	if rec := h.get("/admin/api/clients", cookie); rec.Code != http.StatusOK {
		t.Fatalf("fresh session: status = %d, want 200", rec.Code)
	}

	h.clock.Advance(SessionTTL + time.Second)
	rec := h.get("/admin/api/clients", cookie)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expired session: status = %d, want 401", rec.Code)
	}
	var count int64
	if err := h.store.DB().Model(&store.AdminSession{}).Count(&count).Error; err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	if count != 0 {
		t.Errorf("the expired session row survived (%d rows)", count)
	}
}

// TestUnknownSessionIsRefused: a made-up cookie is not a session.
func TestUnknownSessionIsRefused(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	cookie := &http.Cookie{Name: SessionCookie, Value: "not-a-session-id"}
	if rec := h.get("/admin/api/clients", cookie); rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if rec := h.get("/admin/requests", cookie); rec.Code != http.StatusSeeOther {
		t.Fatalf("page with an unknown session: status = %d, want 303", rec.Code)
	}
}

// TestPagesRedirectAndAPIsRefuse is the split of §9.1: a page without a
// session is redirected to the login page, an API call gets 401 and the
// envelope so the page can react.
func TestPagesRedirectAndAPIsRefuse(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	pages := []string{"/admin/requests", "/admin/clients", "/admin/settings", "/admin/"}
	for _, page := range pages {
		rec := h.get(page, nil)
		if rec.Code != http.StatusSeeOther {
			t.Errorf("%s without a session: status = %d, want 303", page, rec.Code)
			continue
		}
		location := rec.Header().Get("Location")
		if !strings.HasPrefix(location, LoginPath) {
			t.Errorf("%s redirected to %q, want the login page", page, location)
		}
	}

	apis := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/admin/api/clients"},
		{http.MethodGet, "/admin/api/requests"},
		{http.MethodGet, "/admin/api/settings"},
		{http.MethodPost, "/admin/api/settings"},
		{http.MethodPost, "/admin/api/settings/check"},
		{http.MethodPost, "/admin/api/settings/test-telegram"},
		{http.MethodPost, "/admin/api/requests/abc/approve"},
		{http.MethodPost, "/admin/api/requests/abc/reject"},
		{http.MethodPost, "/admin/api/clients/msk-1"},
		{http.MethodPost, "/admin/api/clients/msk-1/enabled"},
		{http.MethodPost, "/admin/api/clients/msk-1/revoke"},
		{http.MethodPost, "/admin/api/clients/msk-1/delete"},
		{http.MethodPost, "/admin/api/logout"},
	}
	for _, api := range apis {
		rec := h.do(h.request(api.method, api.path, nil, testIP))
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s without a session: status = %d, want 401", api.method, api.path, rec.Code)
			continue
		}
		if location := rec.Header().Get("Location"); location != "" {
			t.Errorf("%s %s redirected to %q instead of answering 401", api.method, api.path, location)
		}
		env := decode(t, rec)
		if env.Success {
			t.Errorf("%s %s reports success without a session", api.method, api.path)
		}
		if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
			t.Errorf("%s %s content type = %q, want JSON", api.method, api.path, got)
		}
	}
}

// TestLoginPageAndAssetsNeedNoSession: the two public paths stay public.
func TestLoginPageAndAssetsNeedNoSession(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	if rec := h.get(LoginPath, nil); rec.Code != http.StatusOK {
		t.Errorf("login page: status = %d, want 200", rec.Code)
	}
	if rec := h.get("/admin/assets/vue.global.prod.js", nil); rec.Code != http.StatusOK {
		t.Errorf("asset: status = %d, want 200", rec.Code)
	}
}

// TestLoginPageRedirectsWhenSignedIn keeps a signed-in browser off the card.
func TestLoginPageRedirectsWhenSignedIn(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	cookie := h.signIn()

	rec := h.get(LoginPath, cookie)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", rec.Code)
	}
	if got := rec.Header().Get("Location"); got != RequestsPath {
		t.Errorf("Location = %q, want %q", got, RequestsPath)
	}
}

// TestRedirectCarriesTheAskedForPage: after signing in the browser lands where
// it was going.
func TestRedirectCarriesTheAskedForPage(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	rec := h.get("/admin/settings", nil)
	if got := rec.Header().Get("Location"); got != LoginPath+"?next=%2Fadmin%2Fsettings" {
		t.Fatalf("Location = %q, want the settings page as next", got)
	}

	body := map[string]string{"username": testUser, "password": testPassword, "next": "/admin/settings"}
	rec = h.do(h.request(http.MethodPost, "/admin/api/login", body, testIP))
	var result loginResult
	if err := unmarshalObj(rec, &result); err != nil {
		t.Fatalf("decode obj: %v", err)
	}
	if result.Next != "/admin/settings" {
		t.Errorf("next = %q, want /admin/settings", result.Next)
	}
}

// TestNextIsNeverAnOpenRedirect keeps ?next= inside this server.
func TestNextIsNeverAnOpenRedirect(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{
		"https://evil.example/", "//evil.example/", "/v1/config", "", "/admin/login",
		"\\\\evil", "/admin/api/clients", "/admin/assets/antd.min.js", "/admin/ x",
	} {
		if got := safeNext(raw); !strings.HasPrefix(got, Prefix) || got == LoginPath {
			t.Errorf("safeNext(%q) = %q, want a page of this admin UI", raw, got)
		}
	}
	if got := safeNext("/admin/clients"); got != "/admin/clients" {
		t.Errorf("safeNext kept %q instead of the clients page", got)
	}
}

// TestSessionFromLoginOpensTheAPI walks the whole way: log in, then use the
// cookie that login set on a real endpoint.
func TestSessionFromLoginOpensTheAPI(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	cookie := h.signInWithPassword()

	if rec := h.get("/admin/api/clients", cookie); rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	if rec := h.get("/admin/requests", cookie); rec.Code != http.StatusOK {
		t.Fatalf("page: status = %d, want 200", rec.Code)
	}
}

// TestLogoutDropsTheSession: the row goes and the cookie is cleared.
func TestLogoutDropsTheSession(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	cookie := h.signIn()

	rec := h.post("/admin/api/logout", nil, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	cleared := sessionCookie(t, rec)
	if cleared == nil || cleared.Value != "" || cleared.MaxAge >= 0 {
		t.Fatalf("the cookie was not cleared: %+v", cleared)
	}
	var count int64
	if err := h.store.DB().Model(&store.AdminSession{}).Count(&count).Error; err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	if count != 0 {
		t.Errorf("%d session rows survived the logout", count)
	}
	if rec := h.get("/admin/api/clients", cookie); rec.Code != http.StatusUnauthorized {
		t.Errorf("the session still works after logout: status = %d", rec.Code)
	}
}

// TestLogoutFormRedirects covers the no-JavaScript logout.
func TestLogoutFormRedirects(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	cookie := h.signIn()

	rec := h.post(LogoutPath, nil, cookie)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", rec.Code)
	}
	if got := rec.Header().Get("Location"); got != LoginPath {
		t.Errorf("Location = %q, want %q", got, LoginPath)
	}
}

// TestMutationsArePostOnly: no state changes on a GET, which is what makes
// SameSite=Lax enough without a CSRF token (§9.1).
func TestMutationsArePostOnly(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	cookie := h.signIn()

	mutations := []string{
		"/admin/api/logout",
		"/admin/api/requests/abc/approve",
		"/admin/api/requests/abc/reject",
		"/admin/api/clients/msk-1",
		"/admin/api/clients/msk-1/enabled",
		"/admin/api/clients/msk-1/revoke",
		"/admin/api/clients/msk-1/delete",
		"/admin/api/settings/check",
		"/admin/api/settings/test-telegram",
		"/admin/logout",
	}
	for _, path := range mutations {
		rec := h.get(path, cookie)
		if rec.Code != http.StatusMethodNotAllowed && rec.Code != http.StatusNotFound {
			t.Errorf("GET %s: status = %d, want 405 or 404", path, rec.Code)
		}
	}
	// The settings path answers both verbs: GET reads, POST writes.
	if rec := h.get("/admin/api/settings", cookie); rec.Code != http.StatusOK {
		t.Errorf("GET /admin/api/settings: status = %d, want 200", rec.Code)
	}
}

// TestHumanDuration covers the words the login card prints.
func TestHumanDuration(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   time.Duration
		want string
	}{
		{0, "a second"},
		{900 * time.Millisecond, "a second"},
		{30 * time.Second, "30 seconds"},
		{time.Minute, "a minute"},
		{15 * time.Minute, "15 minutes"},
	}
	for _, c := range cases {
		if got := humanDuration(c.in); got != c.want {
			t.Errorf("humanDuration(%s) = %q, want %q", c.in, got, c.want)
		}
	}
}
