package api

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/SBKubric/3ax-ui-monitoring/internal/registry"
)

// registerMaxBodyBytes bounds a POST /v1/register body (protocol §1's JSON
// discipline, mirrored from the panel contract's own 1 MiB cap) so an
// unauthenticated caller — this route runs before any token exists — can't
// tie up a handler decoding an arbitrarily large body.
const registerMaxBodyBytes = 1 << 20

// registerRequestBody is POST /v1/register's JSON body (protocol §2.1).
// Unknown fields are tolerated, not rejected: architecture brief §1 requires
// mon-server to accept a newer mon-client's extra fields without breaking.
type registerRequestBody struct {
	PairingCode string `json:"pairingCode"`
	Hostname    string `json:"hostname"`
	Version     string `json:"version"`
	PublicIP    string `json:"publicIp"`
}

// RegisterRoutes mounts the two unauthenticated mon-client registration
// endpoints (protocol §2, §8) on v1: POST /register and GET
// /register/:requestId. Neither runs RequireClientToken — a mon-client by
// definition has no client token yet at this point in its life (protocol
// §9: "старт без state-файла").
func RegisterRoutes(v1 *gin.RouterGroup, r *registry.Registry) {
	v1.POST("/register", func(c *gin.Context) { handleRegister(c, r) })
	v1.GET("/register/:requestId", func(c *gin.Context) { handlePoll(c, r) })
}

// handleRegister decodes the body, stamps the connection's own address as
// RemoteIP (never the client-supplied PublicIP, which a hostile caller
// controls and which the rate limits must not be foolable by), and answers
// with the protocol's 202 body on success. A body over registerMaxBodyBytes
// is 413 batch_too_large (the panel contract's own code for the same
// condition, mirrored per protocol §1); any other decode failure — a
// malformed or empty body included, there is no special case for an empty
// one — is 400 invalid_body.
func handleRegister(c *gin.Context, r *registry.Registry) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, registerMaxBodyBytes)
	var body registerRequestBody
	if err := json.NewDecoder(c.Request.Body).Decode(&body); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			Fail(c, http.StatusRequestEntityTooLarge, "batch_too_large", "request body too large")
		} else {
			Fail(c, http.StatusBadRequest, "invalid_body", "decode body: "+err.Error())
		}
		return
	}

	out, err := r.Register(c.Request.Context(), registry.RegisterInput{
		PairingCode: body.PairingCode,
		Hostname:    body.Hostname,
		Version:     body.Version,
		PublicIP:    body.PublicIP,
		RemoteIP:    c.ClientIP(),
	})
	if err != nil {
		failRegister(c, err)
		return
	}

	c.JSON(http.StatusAccepted, gin.H{
		"requestId": out.RequestID,
		"pollAfter": out.PollAfterMs,
		"expiresAt": out.ExpiresAt,
	})
}

// handlePoll answers a mon-client's registration status check (protocol
// §2.2). monClientId/token are only present in the body when the registry
// actually returned them — an approved poll's second call carries no token,
// and gin.H simply omits an unset key rather than serialising "".
func handlePoll(c *gin.Context, r *registry.Registry) {
	out, err := r.Poll(c.Request.Context(), c.Param("requestId"))
	if err != nil {
		failRegister(c, err)
		return
	}

	body := gin.H{"status": out.Status}
	if out.MonClientID != "" {
		body["monClientId"] = out.MonClientID
	}
	if out.Token != "" {
		body["token"] = out.Token
	}
	c.JSON(http.StatusOK, body)
}

// failRegister maps every error Register/Poll can return to the protocol's
// status + {error, message} envelope (protocol §1, §2). An unknown
// requestId always gets the same generic message regardless of whether it
// once existed (protocol §2.1: "без деталей"), so polling never leaks
// whether a given id was ever valid. The default branch is deliberately
// generic too, for a different reason: Register/Poll's only non-sentinel
// errors are internal ones (a DB error, a crypto/rand failure), and their
// Error() text can carry driver detail (a sqlite busy/locked message, a
// file path) that has no business reaching an unauthenticated caller — it
// goes to the log instead, at slog.Error, and the response says nothing
// more than "internal error".
func failRegister(c *gin.Context, err error) {
	var rl *registry.RateLimitError
	switch {
	case errors.As(err, &rl):
		c.Header("Retry-After", strconv.FormatInt(int64(rl.RetryAfter/time.Second), 10))
		Fail(c, http.StatusTooManyRequests, "too_many_requests", err.Error())
	case errors.Is(err, registry.ErrInvalidPairingCode):
		Fail(c, http.StatusBadRequest, "invalid_body", err.Error())
	case errors.Is(err, registry.ErrRequestNotFound):
		Fail(c, http.StatusNotFound, "not_found", "not found")
	case errors.Is(err, registry.ErrRequestExpired):
		Fail(c, http.StatusGone, "request_expired", "registration request expired")
	default:
		slog.Error("register: internal error", "error", err)
		Fail(c, http.StatusInternalServerError, "internal", "internal error")
	}
}
