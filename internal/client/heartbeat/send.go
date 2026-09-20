package heartbeat

import (
	"context"

	"github.com/SBKubric/3ax-ui-monitoring/internal/client/api"
	"github.com/SBKubric/3ax-ui-monitoring/internal/client/proto"
)

// Send posts one heartbeat (protocol §5.3) and returns mon-server's
// answer. It is deliberately one line: the client's *http.Client already
// goes straight to mon-server with no proxy (spec §6: "свой Transport без
// прокси" — the probe is the only thing that ever tunnels), and the
// heartbeatTimeoutMs budget belongs to the caller's ctx, since only the
// run loop knows which config document is currently applied.
//
// It exists at all so the run loop has one named seam for "deliver the
// buffer" — the place a future retry, a compressed body or an alternate
// route would go — instead of reaching into the API client in the middle
// of its cycle bookkeeping.
func Send(ctx context.Context, c *api.Client, hb *proto.HeartbeatRequest) (*proto.HeartbeatResponse, error) {
	return c.Heartbeat(ctx, hb)
}
