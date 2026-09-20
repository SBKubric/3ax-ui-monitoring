package api

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
	"github.com/SBKubric/3ax-ui-monitoring/internal/registry"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
)

// maxNonceLen bounds the `n` query parameter (spec §7.5, protocol §5.2): a
// mon-client only ever needs a short opaque token it can compare against
// the echo, so this is generous headroom over any realistic nonce while
// still keeping a hostile long query string from turning into an
// unbounded database write.
const maxNonceLen = 128

// TargetKeySource is what the probe handler needs from the config builder
// (*registry.ConfigBuilder in production): the set of (inbound, path) pairs
// this mon-client's current document actually names, which is exactly what
// spec §7.5's "unknown_target" flag is checked against. It is spelled out
// as its own interface, distinct from ConfigSource, because the probe
// handler never reads a whole document — only membership in it.
type TargetKeySource interface {
	TargetKeys(ctx context.Context, monClientID string) ([]registry.TargetKey, error)
}

// ProbeRoutes mounts GET /v1/probe (spec §7.5, protocol §5.2) on v1, behind
// RequireClientToken: a tunnel probe proves nothing about which mon-client
// sent it beyond the client token it carries, since the request's source IP
// is the tunnel's own egress, not mon-client's. st is where one probe_seen
// row per request is logged (never internal/store's Target rows — spec
// §7.5: "состояние по этим запросам не считается", state comes only from
// heartbeat); its Clock is also the source of serverTs, kept consistent
// with every other stored timestamp in mon-server (spec §3: ms UTC epoch
// via clock.Clock, never time.Now() directly).
func ProbeRoutes(v1 *gin.RouterGroup, auth ClientAuthenticator, keys TargetKeySource, st *store.Store) {
	v1.GET("/probe", RequireClientToken(auth), func(c *gin.Context) { handleProbe(c, keys, st) })
}

// handleProbe answers spec §7.5's tunnel probe. Two things about it are
// deliberate departures from "handle the happy path, fail otherwise": a
// TargetKeys lookup error and a probe_seen insert error are both logged and
// otherwise ignored rather than turned into a non-200 response, because the
// whole point of the probe from a mon-client's perspective is "did my
// tunnel reach mon-server" — the answer to that question does not depend on
// whether mon-server's own diagnostics bookkeeping succeeded, and failing a
// probe over it would make an unrelated storage hiccup look like a tunnel
// outage.
func handleProbe(c *gin.Context, keys TargetKeySource, st *store.Store) {
	mc := MonClientFrom(c)
	if mc == nil {
		// Unreachable behind RequireClientToken; a wiring mistake, not a
		// client error.
		Fail(c, http.StatusInternalServerError, "internal", "internal error")
		return
	}

	nonce := c.Query("n")
	if nonce == "" || len(nonce) > maxNonceLen {
		Fail(c, http.StatusBadRequest, "bad_request", "missing or oversized n")
		return
	}

	key, ok := parseTarget(c.Query("target"))
	if !ok {
		Fail(c, http.StatusBadRequest, "bad_request", "missing or malformed target")
		return
	}

	ctx := c.Request.Context()
	unknown := isUnknownTarget(ctx, keys, mc.Id, key)

	now := st.Clock.Now()
	row := store.ProbeSeen{
		MonClientId:   mc.Id,
		InboundKind:   key.InboundKind,
		InboundId:     key.InboundID,
		Path:          key.Path,
		EgressIp:      c.ClientIP(),
		SeenAt:        clock.Ms(now),
		UnknownTarget: unknown,
	}
	if err := st.DB.WithContext(ctx).Create(&row).Error; err != nil {
		// Diagnostics-only table (see the doc comment above): log and still
		// answer 200.
		slog.Error("probe: insert probe_seen failed", "monClientId", mc.Id, "error", err)
	}

	c.JSON(http.StatusOK, gin.H{
		"nonce":    nonce,
		"egressIp": c.ClientIP(),
		"serverTs": clock.Ms(now),
	})
}

// isUnknownTarget answers whether key is not among the mon-client's current
// config targets (spec §7.5). A TargetKeys failure (the config builder
// hitting a database error, a decode failure, or anything else short of
// "no config yet") is logged and treated as unknown: mon-server could not
// confirm the target is one it actually handed out, and "unknown" is the
// conservative diagnostic answer, not "known" — it never affects the 200
// response either way (see handleProbe).
func isUnknownTarget(ctx context.Context, keys TargetKeySource, monClientID string, key registry.TargetKey) bool {
	known, err := keys.TargetKeys(ctx, monClientID)
	if err != nil {
		slog.Error("probe: TargetKeys failed", "monClientId", monClientID, "error", err)
		return true
	}
	for _, k := range known {
		if k == key {
			return false
		}
	}
	return true
}

// parseTarget decodes the `target` query parameter's `<kind>:<inboundId>:<path>`
// form (protocol §5.2, e.g. "xray:12:proxy") into a registry.TargetKey, or
// reports ok=false for anything that is not exactly that shape: an unknown
// inbound kind, a negative or non-numeric id, or a path other than the two
// spec §3 defines. There is no reasonable "probe" for a target mon-server
// could never have configured, so this is a 400, not a lenient best-effort
// parse.
func parseTarget(target string) (key registry.TargetKey, ok bool) {
	parts := strings.Split(target, ":")
	if len(parts) != 3 {
		return registry.TargetKey{}, false
	}
	kind, idStr, path := parts[0], parts[1], parts[2]

	switch kind {
	case store.InboundKindXray, store.InboundKindAwg:
	default:
		return registry.TargetKey{}, false
	}
	switch path {
	case store.PathProxy, store.PathDirect:
	default:
		return registry.TargetKey{}, false
	}

	id, err := strconv.Atoi(idStr)
	if err != nil || id < 0 {
		return registry.TargetKey{}, false
	}

	return registry.TargetKey{InboundKind: kind, InboundID: id, Path: path}, true
}
