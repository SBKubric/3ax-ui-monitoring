package api

import (
	"context"
	"net/http"

	"github.com/SBKubric/3ax-ui-monitoring/internal/state"
)

// HeartbeatService applies one heartbeat and answers it (spec mon-server.md
// §7.1). It is implemented by *state.Machine; the handler knows nothing else
// about the state machine.
//
// The mon-client id is the authenticated caller's, not the one in the body:
// the client token decides whose results these are.
type HeartbeatService interface {
	Heartbeat(ctx context.Context, monClientID string, hb state.Heartbeat) (state.HeartbeatAck, error)
}

// RegisterHeartbeatRoutes mounts POST /v1/heartbeat (mon-protocol.md §5.3)
// behind the client token check. The wiring layer calls it once, with the
// state machine as the service.
func RegisterHeartbeatRoutes(s *Server, svc HeartbeatService) {
	s.HandleAuthenticated("POST /v1/heartbeat", heartbeatHandler(s, svc))
}

// heartbeatHandler decodes the heartbeat, hands it to the state machine and
// writes the acknowledgement back.
func heartbeatHandler(s *Server, svc HeartbeatService) AuthHandler {
	return func(w http.ResponseWriter, r *http.Request, id Identity) {
		var hb state.Heartbeat
		if !DecodeJSON(w, r, &hb) {
			return
		}
		if hb.MonClientID != "" && hb.MonClientID != id.MonClientID {
			// Not a failure: the token is the identity. It is worth a line,
			// because it means a mon-client is running someone else's id.
			s.Log().Warn("heartbeat body names another mon-client, using the authenticated one",
				"monClientId", id.MonClientID, "body", hb.MonClientID)
		}
		ack, err := svc.Heartbeat(r.Context(), id.MonClientID, hb)
		if err != nil {
			s.Log().Error("apply heartbeat", "monClientId", id.MonClientID, "error", err)
			WriteError(w, http.StatusInternalServerError, ErrCodeInternal, "could not apply heartbeat")
			return
		}
		WriteJSON(w, http.StatusOK, ack)
	}
}
