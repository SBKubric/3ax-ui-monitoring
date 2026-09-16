// Package api serves the mon-client protocol under /v1 (mon-protocol.md §8).
//
// The package is deliberately assembled from independent route groups: each
// endpoint family lives in its own file and registers itself against a Server
// through Handle or HandleAuthenticated, declaring the service interface it
// needs locally. Nothing has to be added to Server to plug in a new endpoint.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
)

// Error codes returned to mon-clients. They are stable snake_case strings; the
// panel contract and mon-protocol.md §1 use the same envelope.
const (
	ErrCodeTokenRevoked    = "token_revoked"
	ErrCodeDisabled        = "disabled"
	ErrCodeRequestExpired  = "request_expired"
	ErrCodeTooManyRequests = "too_many_requests"
	ErrCodeNotFound        = "not_found"
	ErrCodeInvalidBody     = "invalid_body"
	ErrCodeInternal        = "internal"
)

// Sentinel errors an Authenticator returns; they decide the HTTP status.
var (
	// ErrTokenRevoked means the bearer token is unknown or was revoked: 401.
	ErrTokenRevoked = errors.New("api: client token revoked")
	// ErrClientDisabled means the token is valid but the mon-client is
	// disabled in the admin UI: 403.
	ErrClientDisabled = errors.New("api: mon-client disabled")
)

// Identity is the mon-client behind an authenticated /v1 request.
type Identity struct {
	MonClientID string
}

// Authenticator resolves a raw client token to the mon-client that owns it.
// It is implemented by internal/registry.
type Authenticator interface {
	AuthenticateClient(ctx context.Context, token string) (Identity, error)
}

// Server owns the /v1 mux and the pieces every endpoint shares.
type Server struct {
	auth  Authenticator
	clock clock.Clock
	log   *slog.Logger
	mux   *http.ServeMux
}

// New returns a Server with an empty mux. Route groups register themselves
// afterwards through the Register*Routes function in their own file.
func New(auth Authenticator, clk clock.Clock, log *slog.Logger) *Server {
	return &Server{auth: auth, clock: clk, log: log, mux: http.NewServeMux()}
}

// Handler exposes the mux so the listener can mount it.
func (s *Server) Handler() http.Handler { return s.mux }

// Clock exposes the injected clock to route groups.
func (s *Server) Clock() clock.Clock { return s.clock }

// Log exposes the injected logger to route groups.
func (s *Server) Log() *slog.Logger { return s.log }

// Handle registers an unauthenticated route, e.g. "POST /v1/register".
func (s *Server) Handle(pattern string, h http.HandlerFunc) {
	s.mux.HandleFunc(pattern, h)
}

// AuthHandler is a handler that has already been given the caller's identity.
type AuthHandler func(w http.ResponseWriter, r *http.Request, id Identity)

// HandleAuthenticated registers a route behind the client-token check of
// mon-protocol.md §3: a missing or unknown token is 401 token_revoked, a known
// token belonging to a disabled mon-client is 403 disabled.
func (s *Server) HandleAuthenticated(pattern string, h AuthHandler) {
	s.mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		token, ok := BearerToken(r)
		if !ok {
			WriteError(w, http.StatusUnauthorized, ErrCodeTokenRevoked, "missing bearer token")
			return
		}
		id, err := s.auth.AuthenticateClient(r.Context(), token)
		switch {
		case errors.Is(err, ErrTokenRevoked):
			WriteError(w, http.StatusUnauthorized, ErrCodeTokenRevoked, "unknown or revoked client token")
			return
		case errors.Is(err, ErrClientDisabled):
			WriteError(w, http.StatusForbidden, ErrCodeDisabled, "mon-client is disabled")
			return
		case err != nil:
			s.log.Error("authenticate client", "err", err)
			WriteError(w, http.StatusInternalServerError, ErrCodeInternal, "authentication failed")
			return
		}
		h(w, r, id)
	})
}

// BearerToken pulls the raw token out of an Authorization header.
func BearerToken(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return "", false
	}
	token := strings.TrimSpace(h[len(prefix):])
	return token, token != ""
}

// ClientIP is the source address of the request. mon-server is exposed
// directly to the internet with no reverse proxy in front, so forwarding
// headers are deliberately ignored: registration rate limits (§6) and the
// egressIp a tunnel probe reports back (§7.5) must not be spoofable.
func ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// WriteJSON writes v as the body of a successful response.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if v == nil {
		return
	}
	_ = json.NewEncoder(w).Encode(v)
}

// ErrorBody is the error envelope of mon-protocol.md §1.
type ErrorBody struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
}

// WriteError writes the error envelope with a stable code.
func WriteError(w http.ResponseWriter, status int, code, message string) {
	WriteJSON(w, status, ErrorBody{Error: code, Message: message})
}

// DecodeJSON reads a JSON request body with a 1 MiB cap, rejecting unknown
// fields is deliberately NOT done: the protocol requires tolerating additions.
func DecodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		WriteError(w, http.StatusBadRequest, ErrCodeInvalidBody, err.Error())
		return false
	}
	return true
}
