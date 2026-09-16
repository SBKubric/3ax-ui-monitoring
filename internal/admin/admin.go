// Package admin serves the admin UI of mon-server (spec mon-server.md §9):
// the login and its cookie sessions, the Requests, mon-clients and Settings
// pages, and the JSON API behind them.
//
// Everything lives under /admin/. The pages are html/template documents that
// each boot one Vue 3 application against the Ant Design Vue build embedded in
// web/assets (§9.1): no router, no bundler, and no Node in the Go build. The
// JSON API lives under /admin/api/ and answers with the panel's envelope,
// {"success", "msg", "obj"}.
//
// The package owns sessions, the login lockout and the settings form. It owns
// nothing else: the registry, the panel client, Telegram and the configuration
// rebuild are injected as the narrow interfaces of ports.go, so this package
// never imports internal/registry, internal/panel, internal/tg or
// internal/clientcfg and can be tested with fakes.
//
// The state of targets appears nowhere in this package. That picture belongs
// to the panel's Monitoring page (spec §1, §9.3).
package admin

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
)

// Paths of the admin UI (spec §10).
const (
	// Prefix is where the whole admin UI is mounted.
	Prefix = "/admin/"
	// LoginPath is the only page that does not need a session.
	LoginPath = "/admin/login"
	// LogoutPath ends a session and returns to the login page.
	LogoutPath = "/admin/logout"
	// RequestsPath, ClientsPath and SettingsPath are the three pages.
	RequestsPath = "/admin/requests"
	ClientsPath  = "/admin/clients"
	SettingsPath = "/admin/settings"
	// AssetsPrefix serves the embedded Vue and Ant Design Vue builds. Like
	// the login page it is reachable without a session: the login page loads
	// from it.
	AssetsPrefix = "/admin/assets/"
	// APIPrefix is the JSON API. Without a session it answers 401, never a
	// redirect, so the page can react (§9.1).
	APIPrefix = "/admin/api/"
)

// ServerInfo is the read-only half of the Settings page's "TLS & admin" block
// (§9.4) plus the identity line in the sidebar. mon-server has no settings of
// its own for any of it: the values come from the bootstrap configuration and
// the build, and the wiring layer hands them over as plain values.
type ServerInfo struct {
	// PublicIP and Version are the sidebar's subtitle.
	PublicIP string `json:"publicIp"`
	Version  string `json:"version"`
	// TLSMode is "acme-ip" or "files"; Listen and DataDir come from the
	// bootstrap configuration.
	TLSMode string `json:"tlsMode"`
	Listen  string `json:"listen"`
	DataDir string `json:"dataDir"`
	// CertNotAfter and CertRenewAt are ms UTC, 0 when unknown (they are only
	// known in acme-ip mode once a certificate exists).
	CertNotAfter int64 `json:"certNotAfter"`
	CertRenewAt  int64 `json:"certRenewAt"`
	// AdminHint is the command that changes the login and password. It
	// defaults to DefaultAdminHint.
	AdminHint string `json:"adminHint"`
}

// DefaultAdminHint is the command shown in the TLS & admin block (spec §2).
const DefaultAdminHint = "mon-server admin set <user>"

// RateLimits are the registration limits of spec §6, shown in the header of
// the Requests page (§9.2). They are display values: internal/api enforces
// them.
type RateLimits struct {
	PerIPPerMinute int `json:"perIpPerMinute"`
	PendingPerIP   int `json:"pendingPerIp"`
	PendingGlobal  int `json:"pendingGlobal"`
}

// DefaultRateLimits are the limits of spec §6.
func DefaultRateLimits() RateLimits {
	return RateLimits{PerIPPerMinute: 1, PendingPerIP: 3, PendingGlobal: 20}
}

// Options configures the admin UI. Store and Registry are required; the other
// services may be nil, in which case the buttons that need them report that
// they are not wired instead of panicking.
type Options struct {
	// Store holds sessions, login attempts and the settings (§3).
	Store *store.Store
	// Registry backs the Requests and mon-clients pages.
	Registry Registry
	// Panel runs the Check button, Telegram the Send test button and Configs
	// the rebuild a probe-parameter or realHost change triggers (§9.4).
	Panel    PanelChecker
	Telegram TelegramTester
	Configs  ConfigRebuilder
	// Clock is the injected time source; nil means the system clock.
	Clock clock.Clock
	// Log receives admin UI events. Passwords and session ids are never
	// logged.
	Log *slog.Logger
	// Server is the read-only information of the TLS & admin block.
	Server ServerInfo
	// RateLimits is what the Requests page prints in its header; the zero
	// value means DefaultRateLimits.
	RateLimits RateLimits
}

// Server is the admin UI: its mux, the services it was given and the parsed
// page templates.
type Server struct {
	store    *store.Store
	registry Registry
	panel    PanelChecker
	telegram TelegramTester
	configs  ConfigRebuilder
	clock    clock.Clock
	log      *slog.Logger
	info     ServerInfo
	limits   RateLimits

	pages *pageSet
	mux   *http.ServeMux
}

// New parses the embedded pages and wires the routes of §9.1.
func New(o Options) (*Server, error) {
	if o.Store == nil {
		return nil, errors.New("admin: a store is required")
	}
	if o.Registry == nil {
		return nil, errors.New("admin: a registry is required")
	}
	log := o.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	clk := o.Clock
	if clk == nil {
		clk = clock.System{}
	}
	info := o.Server
	if strings.TrimSpace(info.AdminHint) == "" {
		info.AdminHint = DefaultAdminHint
	}
	limits := o.RateLimits
	if limits == (RateLimits{}) {
		limits = DefaultRateLimits()
	}
	pages, err := parsePages()
	if err != nil {
		return nil, err
	}

	s := &Server{
		store:    o.Store,
		registry: o.Registry,
		panel:    o.Panel,
		telegram: o.Telegram,
		configs:  o.Configs,
		clock:    clk,
		log:      log,
		info:     info,
		limits:   limits,
		pages:    pages,
		mux:      http.NewServeMux(),
	}
	s.routes()
	return s, nil
}

// routes registers every path of §9.1 and §10. Each route says for itself
// whether it needs a session, so an unlisted /admin/* path is a 404 rather
// than something that silently skipped the check.
func (s *Server) routes() {
	// Public: the login page, the login call and the embedded assets.
	s.mux.HandleFunc("GET "+LoginPath, s.loginPage)
	s.mux.HandleFunc("POST "+APIPrefix+"login", s.apiLogin)
	s.mux.HandleFunc("GET "+AssetsPrefix+"{path...}", s.serveAsset)

	// Pages: no session means a redirect to the login page.
	s.mux.HandleFunc("GET /admin/{$}", s.page(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, RequestsPath, http.StatusSeeOther)
	}))
	s.mux.HandleFunc("GET "+RequestsPath, s.page(s.requestsPage))
	s.mux.HandleFunc("GET "+ClientsPath, s.page(s.clientsPage))
	s.mux.HandleFunc("GET "+SettingsPath, s.page(s.settingsPage))
	// A form fallback for logging out without JavaScript. Every mutation is
	// a POST (§9.1: SameSite=Lax is the CSRF defence, so no state changes on
	// a GET).
	s.mux.HandleFunc("POST "+LogoutPath, s.logoutForm)

	// JSON API: no session means 401 with the envelope.
	s.mux.HandleFunc("POST "+APIPrefix+"logout", s.api(s.apiLogout))
	s.mux.HandleFunc("GET "+APIPrefix+"requests", s.api(s.apiRequests))
	s.mux.HandleFunc("POST "+APIPrefix+"requests/{id}/approve", s.api(s.apiApprove))
	s.mux.HandleFunc("POST "+APIPrefix+"requests/{id}/reject", s.api(s.apiReject))
	s.mux.HandleFunc("GET "+APIPrefix+"clients", s.api(s.apiClients))
	s.mux.HandleFunc("POST "+APIPrefix+"clients/{id}", s.api(s.apiUpdateClient))
	s.mux.HandleFunc("POST "+APIPrefix+"clients/{id}/enabled", s.api(s.apiSetEnabled))
	s.mux.HandleFunc("POST "+APIPrefix+"clients/{id}/revoke", s.api(s.apiRevoke))
	s.mux.HandleFunc("POST "+APIPrefix+"clients/{id}/delete", s.api(s.apiDelete))
	s.mux.HandleFunc("GET "+APIPrefix+"settings", s.api(s.apiSettings))
	s.mux.HandleFunc("POST "+APIPrefix+"settings", s.api(s.apiSaveSettings))
	s.mux.HandleFunc("POST "+APIPrefix+"settings/check", s.api(s.apiCheckPanel))
	s.mux.HandleFunc("POST "+APIPrefix+"settings/test-telegram", s.api(s.apiTestTelegram))
}

// Handler is the mux, mounted by internal/server at /admin/ with the prefix
// intact.
func (s *Server) Handler() http.Handler { return s.mux }

// ServeHTTP lets the Server be used as a handler directly.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.mux.ServeHTTP(w, r) }

// nowMS is the current time in ms UTC, from the injected clock.
func (s *Server) nowMS() int64 { return clock.MS(s.clock.Now()) }

// Envelope is the response shape the admin UI shares with the panel (§9.1).
type Envelope struct {
	Success bool   `json:"success"`
	Msg     string `json:"msg"`
	Obj     any    `json:"obj"`
}

// writeEnvelope writes one envelope with the given status.
func writeEnvelope(w http.ResponseWriter, status int, env Envelope) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(env)
}

// writeOK answers 200 with obj.
func writeOK(w http.ResponseWriter, msg string, obj any) {
	writeEnvelope(w, http.StatusOK, Envelope{Success: true, Msg: msg, Obj: obj})
}

// writeFail answers with success:false and a message meant for the
// administrator reading the page.
func writeFail(w http.ResponseWriter, status int, format string, args ...any) {
	writeEnvelope(w, status, Envelope{Success: false, Msg: fmt.Sprintf(format, args...)})
}

// writeServiceError maps an error from an injected service onto a status: the
// sentinels of ports.go are the caller's fault, anything else is ours and is
// logged with the operation that produced it.
func (s *Server) writeServiceError(w http.ResponseWriter, r *http.Request, op string, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		writeFail(w, http.StatusNotFound, "%s", err.Error())
	case errors.Is(err, ErrConflict):
		writeFail(w, http.StatusConflict, "%s", err.Error())
	case errors.Is(err, ErrInvalid):
		writeFail(w, http.StatusBadRequest, "%s", err.Error())
	default:
		s.log.Error("admin operation failed", "op", op, "path", r.URL.Path, "error", err)
		writeFail(w, http.StatusInternalServerError, "%s failed: %s", op, err.Error())
	}
}

// decodeJSON reads a JSON body of at most 1 MiB. It answers 400 itself and
// reports whether the caller may continue. An empty body decodes as the zero
// value, which keeps "no fields to change" from being an error.
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	err := json.NewDecoder(r.Body).Decode(dst)
	switch {
	case err == nil, errors.Is(err, io.EOF):
		return true
	default:
		writeFail(w, http.StatusBadRequest, "malformed request body: %s", err.Error())
		return false
	}
}

// clientIP is the source address of the request.
//
// This is the same rule as api.ClientIP in internal/api/api.go, copied rather
// than imported so that the admin UI does not depend on the mon-client
// protocol package: mon-server is exposed directly to the internet with no
// reverse proxy in front, so forwarding headers are deliberately ignored. The
// login lockout of §9.1 keys on this address and must not be spoofable by a
// header. Both copies must stay identical.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
