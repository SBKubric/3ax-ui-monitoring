package admin

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
)

// Session and lockout parameters (spec §9.1).
const (
	// SessionCookie is the cookie that carries the session id.
	SessionCookie = "mon_session"
	// SessionTTL is how long a session lives from the moment it is issued.
	SessionTTL = 24 * time.Hour
	// SessionIDBytes is how much entropy a session id carries; the cookie
	// value is these bytes in base64url.
	SessionIDBytes = 32
	// MaxLoginFailures is how many failures from one IP lock it out.
	MaxLoginFailures = 5
	// LockoutDuration is how long the lockout lasts.
	LockoutDuration = 15 * time.Minute
)

// newSessionID returns a fresh session id: SessionIDBytes of crypto/rand in
// base64url. The value is never logged.
func newSessionID() (string, error) {
	buf := make([]byte, SessionIDBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("admin: read random bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// issueSession stores a new session for ip and returns its id and expiry.
func (s *Server) issueSession(ip string) (string, time.Time, error) {
	id, err := newSessionID()
	if err != nil {
		return "", time.Time{}, err
	}
	now := s.clock.Now()
	expires := now.Add(SessionTTL)
	row := store.AdminSession{
		ID:        id,
		CreatedAt: clock.MS(now),
		ExpiresAt: clock.MS(expires),
		IP:        ip,
	}
	if err := s.store.DB().Create(&row).Error; err != nil {
		return "", time.Time{}, fmt.Errorf("admin: store session: %w", err)
	}
	return id, expires, nil
}

// session returns the live session the request carries. An unknown or expired
// id is not a session; an expired row is dropped on the way past, so the
// retention job is a backstop rather than the only cleaner.
func (s *Server) session(r *http.Request) (store.AdminSession, bool, error) {
	cookie, err := r.Cookie(SessionCookie)
	if err != nil || strings.TrimSpace(cookie.Value) == "" {
		return store.AdminSession{}, false, nil
	}
	var row store.AdminSession
	err = s.store.DB().Where("id = ?", cookie.Value).Take(&row).Error
	switch {
	case errors.Is(err, gorm.ErrRecordNotFound):
		return store.AdminSession{}, false, nil
	case err != nil:
		return store.AdminSession{}, false, fmt.Errorf("admin: read session: %w", err)
	}
	if row.ExpiresAt <= s.nowMS() {
		if err := s.dropSession(row.ID); err != nil {
			s.log.Warn("could not drop an expired session", "error", err)
		}
		return store.AdminSession{}, false, nil
	}
	return row, true, nil
}

// dropSession deletes one session row.
func (s *Server) dropSession(id string) error {
	if err := s.store.DB().Where("id = ?", id).Delete(&store.AdminSession{}).Error; err != nil {
		return fmt.Errorf("admin: delete session: %w", err)
	}
	return nil
}

// setSessionCookie writes the session cookie of §9.1: HttpOnly so no script
// can read it, Secure because mon-server only ever serves HTTPS, and
// SameSite=Lax so a cross-site form cannot drive the admin API. The lifetime
// matches the row in admin_sessions.
func setSessionCookie(w http.ResponseWriter, id string, expires time.Time, now time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookie,
		Value:    id,
		Path:     Prefix,
		Expires:  expires,
		MaxAge:   int(expires.Sub(now).Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

// clearSessionCookie expires the cookie in the browser. The row is deleted
// separately; both happen on logout.
func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookie,
		Value:    "",
		Path:     Prefix,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

// page wraps a page handler with the session check: without a session the
// browser is sent to the login page (§9.1).
func (s *Server) page(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, ok, err := s.session(r)
		if err != nil {
			s.log.Error("session lookup failed", "path", r.URL.Path, "error", err)
			http.Error(w, "session lookup failed", http.StatusInternalServerError)
			return
		}
		if !ok {
			http.Redirect(w, r, loginRedirect(r), http.StatusSeeOther)
			return
		}
		h(w, r)
	}
}

// api wraps a JSON handler with the session check: without a session it is
// 401 with the envelope and never a redirect, so the page can show the login
// screen instead of parsing an HTML body (§9.1).
func (s *Server) api(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, ok, err := s.session(r)
		if err != nil {
			s.log.Error("session lookup failed", "path", r.URL.Path, "error", err)
			writeFail(w, http.StatusInternalServerError, "session lookup failed")
			return
		}
		if !ok {
			writeFail(w, http.StatusUnauthorized, "not signed in")
			return
		}
		h(w, r)
	}
}

// loginRedirect is where a page request without a session goes. The path that
// was asked for rides along as ?next= so the login page can return to it; only
// pages of this admin UI are ever echoed back.
func loginRedirect(r *http.Request) string {
	next := safeNext(r.URL.Path)
	return LoginPath + "?" + url.Values{"next": []string{next}}.Encode()
}

// safeNext sanitises the ?next= parameter into a page this server owns, so it
// can never become an open redirect and never lands the browser on a JSON
// endpoint or an asset.
func safeNext(raw string) string {
	switch {
	case raw == "", raw == LoginPath, raw == LogoutPath,
		!strings.HasPrefix(raw, Prefix),
		strings.HasPrefix(raw, "//"),
		strings.HasPrefix(raw, APIPrefix),
		strings.HasPrefix(raw, AssetsPrefix),
		strings.ContainsAny(raw, "\\ \t\r\n"):
		return RequestsPath
	}
	return raw
}

// lockState is what the login lockout of §9.1 knows about one IP.
type lockState struct {
	// Locked is true while the IP is refused outright, with Retry left to
	// wait.
	Locked bool
	Retry  time.Duration
	// Left is how many failures remain before the lockout.
	Left int
}

// loginAllowed reports whether an IP may attempt a login. Five failures lock
// it out for fifteen minutes; once the window has passed the counter starts
// again, so the next failure does not lock it immediately.
func (s *Server) loginAllowed(ip string) (lockState, error) {
	row, found, err := s.attempt(ip)
	if err != nil {
		return lockState{}, err
	}
	if !found {
		return lockState{Left: MaxLoginFailures}, nil
	}
	now := s.nowMS()
	if row.LockedUntil > now {
		return lockState{Locked: true, Retry: time.Duration(row.LockedUntil-now) * time.Millisecond}, nil
	}
	if row.LockedUntil != 0 {
		// The lockout has expired: forget the failures behind it.
		if err := s.clearAttempts(ip); err != nil {
			return lockState{}, err
		}
		return lockState{Left: MaxLoginFailures}, nil
	}
	left := MaxLoginFailures - row.Failures
	if left < 0 {
		left = 0
	}
	return lockState{Left: left}, nil
}

// recordFailure counts one failed login and locks the IP out on the fifth.
func (s *Server) recordFailure(ip string) (lockState, error) {
	row, _, err := s.attempt(ip)
	if err != nil {
		return lockState{}, err
	}
	row.IP = ip
	row.Failures++
	row.LockedUntil = 0
	state := lockState{Left: MaxLoginFailures - row.Failures}
	if row.Failures >= MaxLoginFailures {
		until := s.clock.Now().Add(LockoutDuration)
		row.LockedUntil = clock.MS(until)
		state = lockState{Locked: true, Retry: LockoutDuration}
	}
	if state.Left < 0 {
		state.Left = 0
	}
	err = s.store.DB().Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "ip"}},
		DoUpdates: clause.AssignmentColumns([]string{"failures", "locked_until"}),
	}).Create(&row).Error
	if err != nil {
		return lockState{}, fmt.Errorf("admin: write login attempt: %w", err)
	}
	return state, nil
}

// clearAttempts forgets the failures of an IP, which a successful login does.
func (s *Server) clearAttempts(ip string) error {
	if err := s.store.DB().Where("ip = ?", ip).Delete(&store.LoginAttempt{}).Error; err != nil {
		return fmt.Errorf("admin: clear login attempts: %w", err)
	}
	return nil
}

// attempt reads the login_attempts row of one IP.
func (s *Server) attempt(ip string) (store.LoginAttempt, bool, error) {
	var row store.LoginAttempt
	err := s.store.DB().Where("ip = ?", ip).Take(&row).Error
	switch {
	case err == nil:
		return row, true, nil
	case errors.Is(err, gorm.ErrRecordNotFound):
		return store.LoginAttempt{IP: ip}, false, nil
	default:
		return store.LoginAttempt{}, false, fmt.Errorf("admin: read login attempts: %w", err)
	}
}

// loginRequest is the body of POST /admin/api/login.
type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Next     string `json:"next"`
}

// loginResult is the obj of a login response: what the login card shows next.
type loginResult struct {
	// Next is where the page should go after a successful login.
	Next string `json:"next,omitempty"`
	// AttemptsLeft counts down to the lockout, RetrySeconds is how long a
	// locked-out IP has to wait.
	AttemptsLeft int   `json:"attemptsLeft"`
	RetrySeconds int64 `json:"retrySeconds,omitempty"`
	// Locked is true while this IP is locked out.
	Locked bool `json:"locked,omitempty"`
}

// apiLogin checks the credentials against store.CheckAdmin (bcrypt) and issues
// the session cookie. Neither the password nor the session id is ever logged.
func (s *Server) apiLogin(w http.ResponseWriter, r *http.Request) {
	var body loginRequest
	if !decodeJSON(w, r, &body) {
		return
	}
	ip := clientIP(r)

	state, err := s.loginAllowed(ip)
	if err != nil {
		s.log.Error("login lockout lookup failed", "ip", ip, "error", err)
		writeFail(w, http.StatusInternalServerError, "login failed")
		return
	}
	if state.Locked {
		// The password is not even looked at: the lockout is by IP (§9.1).
		s.log.Warn("login refused, ip locked out", "ip", ip, "retryInSeconds", int64(state.Retry.Seconds()))
		w.Header().Set("Retry-After", strconv.FormatInt(int64(state.Retry.Seconds()+0.5), 10))
		writeEnvelope(w, http.StatusTooManyRequests, Envelope{
			Msg: fmt.Sprintf("Too many failed attempts from this address. Try again in %s.", humanDuration(state.Retry)),
			Obj: loginResult{Locked: true, RetrySeconds: int64(state.Retry.Seconds() + 0.5)},
		})
		return
	}

	okAuth, err := s.store.CheckAdmin(body.Username, body.Password)
	if err != nil {
		s.log.Error("credential check failed", "ip", ip, "error", err)
		writeFail(w, http.StatusInternalServerError, "login failed")
		return
	}
	if !okAuth {
		after, err := s.recordFailure(ip)
		if err != nil {
			s.log.Error("could not record a failed login", "ip", ip, "error", err)
			writeFail(w, http.StatusInternalServerError, "login failed")
			return
		}
		s.log.Warn("failed admin login", "ip", ip, "attemptsLeft", after.Left)
		if after.Locked {
			w.Header().Set("Retry-After", strconv.FormatInt(int64(after.Retry.Seconds()+0.5), 10))
			writeEnvelope(w, http.StatusTooManyRequests, Envelope{
				Msg: fmt.Sprintf("Too many failed attempts from this address. Try again in %s.", humanDuration(after.Retry)),
				Obj: loginResult{Locked: true, RetrySeconds: int64(after.Retry.Seconds() + 0.5)},
			})
			return
		}
		writeEnvelope(w, http.StatusUnauthorized, Envelope{
			Msg: "Wrong username or password.",
			Obj: loginResult{AttemptsLeft: after.Left},
		})
		return
	}

	if err := s.clearAttempts(ip); err != nil {
		s.log.Error("could not clear login attempts", "ip", ip, "error", err)
		writeFail(w, http.StatusInternalServerError, "login failed")
		return
	}
	id, expires, err := s.issueSession(ip)
	if err != nil {
		s.log.Error("could not issue a session", "ip", ip, "error", err)
		writeFail(w, http.StatusInternalServerError, "login failed")
		return
	}
	setSessionCookie(w, id, expires, s.clock.Now())
	s.log.Info("admin signed in", "ip", ip)
	writeOK(w, "Signed in.", loginResult{Next: safeNext(body.Next), AttemptsLeft: MaxLoginFailures})
}

// apiLogout deletes the session row and clears the cookie.
func (s *Server) apiLogout(w http.ResponseWriter, r *http.Request) {
	if row, ok, err := s.session(r); err == nil && ok {
		if err := s.dropSession(row.ID); err != nil {
			s.log.Error("could not delete a session", "error", err)
		}
	}
	clearSessionCookie(w)
	writeOK(w, "Signed out.", loginResult{Next: LoginPath})
}

// logoutForm is the no-JavaScript logout: same effect, then back to the login
// page.
func (s *Server) logoutForm(w http.ResponseWriter, r *http.Request) {
	if row, ok, err := s.session(r); err == nil && ok {
		if err := s.dropSession(row.ID); err != nil {
			s.log.Error("could not delete a session", "error", err)
		}
	}
	clearSessionCookie(w)
	http.Redirect(w, r, LoginPath, http.StatusSeeOther)
}

// humanDuration renders a lockout as the login card prints it.
func humanDuration(d time.Duration) string {
	if d < time.Minute {
		seconds := int(d.Seconds() + 0.5)
		if seconds <= 1 {
			return "a second"
		}
		return fmt.Sprintf("%d seconds", seconds)
	}
	minutes := int(d.Minutes() + 0.5)
	if minutes == 1 {
		return "a minute"
	}
	return fmt.Sprintf("%d minutes", minutes)
}
