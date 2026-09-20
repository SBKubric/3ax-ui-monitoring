package api

import (
	"errors"
	"fmt"
	"time"
)

// ErrTokenRevoked is every method's answer to a 401 (protocol §3: the token
// is unknown or was revoked). The caller (internal/client/app, step 9)
// reacts by stopping probes, clearing the state file and registering again
// (protocol §2.3).
var ErrTokenRevoked = errors.New("api: token revoked")

// ErrDisabled is every method's answer to a 403 (protocol §3: the token is
// known but this mon-client is disabled in the admin UI). The caller keeps
// its state file and retries a heartbeat every 5 minutes (spec §6) rather
// than re-registering.
var ErrDisabled = errors.New("api: mon-client disabled")

// ErrRequestExpired is Poll's answer to a 410 (protocol §2.1: a
// registration request's 5-minute TTL passed). The caller starts a new
// registration with a new pairing code (spec §3).
var ErrRequestExpired = errors.New("api: registration request expired")

// RateLimitError is Register's answer to a 429 (protocol §2.1's per-IP and
// global registration limits). RetryAfter comes from the response's
// Retry-After header, in whole seconds per HTTP semantics; a response
// without one, or with a header this package cannot parse, keeps
// RetryAfter at zero, which the caller should treat as "retry with its own
// backoff" rather than as "retry immediately".
type RateLimitError struct {
	RetryAfter time.Duration
}

func (e *RateLimitError) Error() string {
	return fmt.Sprintf("api: rate limited, retry after %s", e.RetryAfter)
}

// StatusError is the catch-all for any other non-2xx response: an
// unrecognised 4xx (protocol's own {error, message} envelope, spec §1) or
// any 5xx. Status/Code/Message are kept apart — rather than folded into
// Error()'s string alone — so a caller that needs to branch on one of them
// (GET /v1/config's 503 config_not_ready, spelled out in the brief as "the
// caller treats as empty config, retry next cycle") can do so by field
// instead of parsing a formatted string back apart.
type StatusError struct {
	Status  int
	Code    string
	Message string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("api: %d %s: %s", e.Status, e.Code, e.Message)
}

// NetError wraps a transport-level failure (dial refused, connection reset,
// TLS handshake failure, a deadline expiring before or during the round
// trip) — anything that never produced an HTTP response at all. Op names
// the call that failed ("register", "poll", "config", "heartbeat") so a log
// line built from an unwrapped NetError still says what mon-client was
// trying to do.
type NetError struct {
	Op  string
	Err error
}

func (e *NetError) Error() string { return fmt.Sprintf("api: %s: %v", e.Op, e.Err) }
func (e *NetError) Unwrap() error { return e.Err }

// Timeout reports whether the underlying failure was a deadline expiring —
// http.Client's own transport errors implement this the same way
// net.Error does, so callers that only care about "did this time out"
// (the registration backoff treats a network timeout the same as any other
// network error, protocol §2.1) can check it without a type switch on the
// wrapped error's concrete type.
func (e *NetError) Timeout() bool {
	var te interface{ Timeout() bool }
	if errors.As(e.Err, &te) {
		return te.Timeout()
	}
	return false
}
