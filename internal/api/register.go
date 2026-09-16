package api

import (
	"context"
	"errors"
	"math"
	"net/http"
	"strconv"
	"time"
)

// Registration endpoints, mon-protocol.md §2: the only two /v1 routes a
// mon-client may call without a client token.
//
// The wire shapes and the service port live here rather than in
// internal/registry because internal/registry implements Authenticator and so
// already depends on this package; the registry aliases the three types below
// so that one set of structs crosses the boundary in one direction only.

// Sentinel errors a RegistrationService returns. They are what the handler
// branches on, so the registry speaks them instead of HTTP statuses.
var (
	// ErrRegistrationInvalid is a request that cannot be accepted as written,
	// a malformed pairing code being the usual cause: 400 invalid_body.
	ErrRegistrationInvalid = errors.New("api: invalid registration request")
	// ErrRegistrationRateLimited is one of the limits of spec §6 refusing the
	// request: 429 too_many_requests with a Retry-After. The error may also
	// carry a RetryAfter() time.Duration, which becomes the header value.
	ErrRegistrationRateLimited = errors.New("api: registration rate limit reached")
	// ErrRegistrationNotFound is an unknown requestId: a bare 404, with no
	// body at all.
	ErrRegistrationNotFound = errors.New("api: registration request not found")
	// ErrRegistrationExpired is a request past its five minutes:
	// 410 request_expired.
	ErrRegistrationExpired = errors.New("api: registration request expired")
)

// RegistrationSubmit is one POST /v1/register: what the mon-client sent plus
// the address it actually came from.
type RegistrationSubmit struct {
	// PairingCode is the [A-Z2-9]{6} code the mon-client generated and
	// printed to its log; mon-server only checks its shape.
	PairingCode string
	Hostname    string
	Version     string
	// PublicIP is the address the box believes it has, RemoteIP the one the
	// connection came from. They differ behind NAT, and only RemoteIP is
	// trustworthy, so the rate limits count that one.
	PublicIP string
	RemoteIP string
}

// RegistrationSubmitted is the 202 answer to POST /v1/register.
type RegistrationSubmitted struct {
	// RequestID is the polling secret: 128 random bits in base64url.
	RequestID string
	// PollAfterMS is how long the mon-client waits between polls.
	PollAfterMS int64
	// ExpiresAt is ms UTC of the request's five minute deadline.
	ExpiresAt int64
}

// RegistrationStatus is the 200 answer to GET /v1/register/{requestId}.
// MonClientID and Token are set only for an approved request, and Token only
// on the first poll that collects it.
type RegistrationStatus struct {
	Status      string
	MonClientID string
	Token       string
}

// RegistrationService is the part of the registry the two registration routes
// need (implemented by *registry.Registry).
type RegistrationService interface {
	Submit(ctx context.Context, req RegistrationSubmit) (RegistrationSubmitted, error)
	Poll(ctx context.Context, requestID string) (RegistrationStatus, error)
}

// RegisterRegistrationRoutes mounts POST /v1/register and
// GET /v1/register/{requestId} on s (mon-protocol.md §2).
func RegisterRegistrationRoutes(s *Server, svc RegistrationService) {
	s.Handle("POST /v1/register", func(w http.ResponseWriter, r *http.Request) {
		var body registerSubmitBody
		if !DecodeJSON(w, r, &body) {
			return
		}
		res, err := svc.Submit(r.Context(), RegistrationSubmit{
			PairingCode: body.PairingCode,
			Hostname:    body.Hostname,
			Version:     body.Version,
			PublicIP:    body.PublicIP,
			RemoteIP:    ClientIP(r),
		})
		switch {
		case errors.Is(err, ErrRegistrationInvalid):
			WriteError(w, http.StatusBadRequest, ErrCodeInvalidBody, err.Error())
		case errors.Is(err, ErrRegistrationRateLimited):
			w.Header().Set("Retry-After", strconv.FormatInt(registerRetryAfterSeconds(err), 10))
			WriteError(w, http.StatusTooManyRequests, ErrCodeTooManyRequests, err.Error())
		case err != nil:
			s.Log().Error("accept registration request", "err", err)
			WriteError(w, http.StatusInternalServerError, ErrCodeInternal, "could not accept the registration request")
		default:
			WriteJSON(w, http.StatusAccepted, registerAcceptedBody{
				RequestID: res.RequestID,
				PollAfter: res.PollAfterMS,
				ExpiresAt: res.ExpiresAt,
			})
		}
	})

	s.Handle("GET /v1/register/{requestId}", func(w http.ResponseWriter, r *http.Request) {
		res, err := svc.Poll(r.Context(), r.PathValue("requestId"))
		switch {
		case errors.Is(err, ErrRegistrationNotFound):
			// A bare 404 with no body: the requestId is a secret, and an
			// error envelope would tell a guesser that ids exist to be found
			// (mon-protocol.md §2.1).
			w.WriteHeader(http.StatusNotFound)
		case errors.Is(err, ErrRegistrationExpired):
			WriteError(w, http.StatusGone, ErrCodeRequestExpired, "registration request expired")
		case err != nil:
			s.Log().Error("poll registration request", "err", err)
			WriteError(w, http.StatusInternalServerError, ErrCodeInternal, "could not read the registration request")
		default:
			WriteJSON(w, http.StatusOK, registerStatusBody{
				Status:      res.Status,
				MonClientID: res.MonClientID,
				Token:       res.Token,
			})
		}
	})
}

// registerSubmitBody is the body of POST /v1/register (mon-protocol.md §2.1).
type registerSubmitBody struct {
	PairingCode string `json:"pairingCode"`
	Hostname    string `json:"hostname"`
	Version     string `json:"version"`
	PublicIP    string `json:"publicIp"`
}

// registerAcceptedBody is the 202 answer.
type registerAcceptedBody struct {
	RequestID string `json:"requestId"`
	PollAfter int64  `json:"pollAfter"`
	ExpiresAt int64  `json:"expiresAt"`
}

// registerStatusBody is the 200 answer to a poll. monClientId and token are
// omitted unless the request is approved, and token also once it has been
// collected: the plaintext is handed out exactly once.
type registerStatusBody struct {
	Status      string `json:"status"`
	MonClientID string `json:"monClientId,omitempty"`
	Token       string `json:"token,omitempty"`
}

// registerDefaultRetryAfter is the Retry-After used when a rate-limit error
// carries no hint of its own.
const registerDefaultRetryAfter = time.Minute

// registerRetryAfterHint is implemented by the registry's rate-limit errors.
// Matching it structurally keeps this package free of a dependency on the
// registry, which depends on it.
type registerRetryAfterHint interface {
	RetryAfter() time.Duration
}

// registerRetryAfterSeconds turns a rate-limit error into the Retry-After
// header value: whole seconds, never below one.
func registerRetryAfterSeconds(err error) int64 {
	wait := registerDefaultRetryAfter
	var hint registerRetryAfterHint
	if errors.As(err, &hint) {
		wait = hint.RetryAfter()
	}
	secs := int64(math.Ceil(wait.Seconds()))
	if secs < 1 {
		secs = 1
	}
	return secs
}
