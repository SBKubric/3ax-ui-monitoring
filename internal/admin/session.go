package admin

import (
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
)

// SessionCookie is the name of the admin UI's session cookie (spec §9.1:
// "cookie-сессия mon_session"). It is exported so the e2e harness and this
// package's tests name it once, from here.
const SessionCookie = "mon_session"

// cookiePath scopes the session cookie to the admin UI. /v1/* is the
// mon-client protocol and authenticates with a bearer token; it must never
// see this cookie, and a browser that wanders there should not send it.
const cookiePath = "/admin"

// loginPath is where an unauthenticated page request is sent (spec §9.1:
// "все /admin/*, кроме /admin/login, требуют сессию").
const loginPath = "/admin/login"

// sessionKey is the gin context key the resolved session is stashed under,
// so a handler that needs the current session (logout) does not look it up
// a second time.
const sessionKey = "adminSession"

// RequireSession is the gate in front of everything but the login page and
// the embedded assets (spec §9.1). page selects what an unauthenticated
// request gets: a browser asking for a page is redirected to the login form
// with ?next= so it lands back where it was going, while /admin/api/* gets
// 401 with the usual envelope — a Vue application must never receive the
// login page's HTML where it expects JSON.
func (h *Handler) RequireSession(page bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		sess, err := h.currentSession(c)
		if err != nil {
			if page {
				c.Redirect(http.StatusFound, loginPath+"?next="+url.QueryEscape(c.Request.URL.RequestURI()))
				c.Abort()
				return
			}
			fail(c, http.StatusUnauthorized, "Not signed in.")
			return
		}
		c.Set(sessionKey, sess)
		c.Next()
	}
}

// currentSession resolves the request's cookie to a live session row, or
// reports store.ErrSessionNotFound. Every failure mode — no cookie, unknown
// id, expired row — looks the same to the caller on purpose (see
// store.ErrSessionNotFound).
func (h *Handler) currentSession(c *gin.Context) (*store.AdminSession, error) {
	raw, err := c.Cookie(SessionCookie)
	if err != nil || raw == "" {
		return nil, store.ErrSessionNotFound
	}
	return h.deps.Store.Session(raw)
}

// setSessionCookie installs the session cookie with the attributes spec §9.1
// fixes: HttpOnly (no script can read it, so an XSS in a third-party CDN
// script could not exfiltrate it), Secure (mon-server only ever serves
// HTTPS, spec §2), SameSite=Lax (a cross-site POST carries no cookie, which
// together with the X-Requested-With guard is this UI's whole CSRF defence)
// and the same 24 h lifetime as the row behind it.
func (h *Handler) setSessionCookie(c *gin.Context, id string) {
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(SessionCookie, id, int(store.SessionTTL.Seconds()), cookiePath, "", true, true)
}

// clearSessionCookie expires the cookie on logout. The row is deleted too
// (see logout); clearing the cookie only saves the browser from sending a
// value that is already dead.
func (h *Handler) clearSessionCookie(c *gin.Context) {
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(SessionCookie, "", -1, cookiePath, "", true, true)
}

// loginPage renders the login form, or sends an administrator who already
// has a live session straight on to where they were going — a browser that
// still holds a valid cookie has no business being shown a password field.
func (h *Handler) loginPage(c *gin.Context) {
	if _, err := h.currentSession(c); err == nil {
		c.Redirect(http.StatusFound, safeNext(c.Query("next")))
		return
	}
	h.render(c, "login", gin.H{"Next": safeNext(c.Query("next"))})
}

// loginRequest is the login form's body. It is JSON because the login page
// is a Vue application like every other page here; the fields are the same
// two spec §9.1 names ("логин + пароль").
type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Next     string `json:"next"`
}

// login checks credentials against the single admin row and issues a
// session (spec §9.1). The order matters: the per-IP lockout is consulted
// *before* bcrypt runs, so a locked-out IP cannot keep burning CPU, and a
// successful login clears the IP's failure streak.
//
// Every failure answers with the same message whatever went wrong —
// unknown user, wrong password — because there is exactly one account and
// telling the two apart would only help someone guessing at it.
func (h *Handler) login(c *gin.Context) {
	ip := c.ClientIP()

	locked, remaining, err := h.deps.Store.LoginLocked(ip)
	if err != nil {
		slog.Error("admin: reading the login lockout failed", "err", err)
		fail(c, http.StatusInternalServerError, "Could not check the login lockout.")
		return
	}
	if locked {
		fail(c, http.StatusTooManyRequests, "Too many failed logins from this IP. Try again in "+roundMinutes(remaining)+".")
		return
	}

	var req loginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		fail(c, http.StatusBadRequest, "Malformed login request.")
		return
	}

	good, err := h.deps.Store.CheckAdmin(req.Username, req.Password)
	if err != nil {
		slog.Error("admin: checking the administrator password failed", "err", err)
		fail(c, http.StatusInternalServerError, "Could not check the password.")
		return
	}
	if !good {
		nowLocked, left, err := h.deps.Store.RecordLoginFailure(ip)
		if err != nil {
			slog.Error("admin: recording a failed login failed", "err", err)
		}
		if nowLocked {
			fail(c, http.StatusTooManyRequests, "Too many failed logins from this IP. Try again in "+roundMinutes(store.LoginLockout)+".")
			return
		}
		c.AbortWithStatusJSON(http.StatusUnauthorized, envelope{
			Success: false,
			Msg:     "Wrong login or password.",
			Obj:     gin.H{"attemptsLeft": left},
		})
		return
	}

	if err := h.deps.Store.ResetLoginAttempts(ip); err != nil {
		slog.Error("admin: clearing the login failure streak failed", "err", err)
	}
	sess, err := h.deps.Store.CreateSession(ip)
	if err != nil {
		slog.Error("admin: creating an admin session failed", "err", err)
		fail(c, http.StatusInternalServerError, "Could not start a session.")
		return
	}
	h.setSessionCookie(c, sess.Id)
	okMsg(c, "Signed in.", gin.H{"next": safeNext(req.Next)})
}

// logout deletes the session row and clears the cookie (spec §9.1). It is
// deliberately tolerant of a request with no session at all: "log me out"
// when already logged out is a success, not an error.
func (h *Handler) logout(c *gin.Context) {
	if raw, err := c.Cookie(SessionCookie); err == nil && raw != "" {
		if err := h.deps.Store.DeleteSession(raw); err != nil {
			slog.Error("admin: deleting an admin session failed", "err", err)
		}
	}
	h.clearSessionCookie(c)
	okMsg(c, "Signed out.", gin.H{"next": loginPath})
}

// safeNext sanitises the ?next= parameter into somewhere inside this admin
// UI. Anything else — an absolute URL, a scheme-relative //evil.example, a
// path outside /admin — falls back to the Requests page, so the login form
// can never be turned into an open redirect.
func safeNext(next string) string {
	if next == "" || !strings.HasPrefix(next, "/admin") || strings.HasPrefix(next, "//") {
		return "/admin/requests"
	}
	if next == loginPath || strings.HasPrefix(next, loginPath+"?") {
		return "/admin/requests"
	}
	return next
}

// roundMinutes renders a lockout remainder the way the login page says it
// ("try again in 15 minutes"), rounding up so it never tells an
// administrator to retry a moment before the lock actually lifts.
func roundMinutes(d time.Duration) string {
	m := int(d.Minutes())
	if time.Duration(m)*time.Minute < d {
		m++
	}
	if m <= 1 {
		return "a minute"
	}
	return strconv.Itoa(m) + " minutes"
}
