package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/SBKubric/3ax-ui-monitoring/internal/state"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
)

// maxHeartbeatBody bounds the POST /v1/heartbeat body at 1 MiB. A
// mon-client buffers at most 60 cycles (protocol §5.3) of a few dozen
// results each, which is orders of magnitude smaller; the limit exists so
// an authenticated but misbehaving (or compromised) box cannot make
// mon-server allocate unbounded memory by streaming an endless body.
const maxHeartbeatBody = 1 << 20

// HeartbeatEngine is the part of *state.Engine this handler needs: one
// call that applies the heartbeat and returns the protocol's answer. Naming
// it here keeps internal/api free of any knowledge of the state machine
// itself and lets this package's tests drive the handler from a stub.
type HeartbeatEngine interface {
	Heartbeat(ctx context.Context, mc *store.MonClient, hb *state.HeartbeatRequest) (*state.HeartbeatResponse, error)
}

// HeartbeatRoutes mounts POST /v1/heartbeat (protocol §5.3) on v1, behind
// RequireClientToken: a heartbeat decides a mon-client's state and every
// one of its targets', so it is only ever accepted from an authenticated,
// enabled mon-client — and only about itself.
func HeartbeatRoutes(v1 *gin.RouterGroup, auth ClientAuthenticator, eng HeartbeatEngine) {
	v1.POST("/heartbeat", RequireClientToken(auth), func(c *gin.Context) { handleHeartbeat(c, eng) })
}

// handleHeartbeat decodes the body, checks it is about the caller itself,
// and hands it to the engine.
//
// The monClientId in the body is checked against the token's rather than
// trusted: it is in the protocol so a mon-client can catch its own
// misconfiguration, and a mismatch means someone is trying to write
// another box's state — 400 bad_request, not a silent correction, because
// silently applying it to the authenticated id would hide the mistake from
// whoever has to debug it.
func handleHeartbeat(c *gin.Context, eng HeartbeatEngine) {
	mc := MonClientFrom(c)
	if mc == nil {
		// Unreachable behind RequireClientToken; a wiring mistake, not a
		// client error.
		Fail(c, http.StatusInternalServerError, "internal", "internal error")
		return
	}

	body := http.MaxBytesReader(c.Writer, c.Request.Body, maxHeartbeatBody)
	var hb state.HeartbeatRequest
	// The protocol (§1) requires both sides to tolerate fields they do not
	// know, so the decoder is deliberately lenient — no DisallowUnknownFields.
	if err := json.NewDecoder(body).Decode(&hb); err != nil {
		Fail(c, http.StatusBadRequest, "invalid_body", "body is not a valid heartbeat document")
		return
	}
	if hb.MonClientID != mc.Id {
		Fail(c, http.StatusBadRequest, "bad_request", "monClientId does not match the authenticated mon-client")
		return
	}

	resp, err := eng.Heartbeat(c.Request.Context(), mc, &hb)
	if err != nil {
		// A failure here is mon-server's own (the database, the settings
		// table): its text can carry driver detail that has no business
		// reaching a mon-client, so it goes to the log and the mon-client
		// gets a 5xx it will retry — the heartbeat's cycles stay in its
		// buffer and arrive again (protocol §5.3).
		slog.Error("heartbeat: applying failed", "monClientId", mc.Id, "error", err)
		Fail(c, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	c.JSON(http.StatusOK, resp)
}
