package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/SBKubric/3ax-ui-monitoring/internal/registry"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
)

// ClientAuthenticator is what RequireClientToken needs from the registry.
// It is spelled out as a named type here (rather than only inline in
// RequireClientToken's signature) so every route-registration function can
// name the same dependency, and so this package's tests can pass a stub.
type ClientAuthenticator interface {
	Authenticate(ctx context.Context, clientToken string) (*store.MonClient, error)
}

// ConfigSource is the config document store GET /v1/config reads
// (*registry.ConfigBuilder in production). Only Current is needed: the
// handler never builds or compares revisions itself, it hands the
// mon-client whatever the builder considers current.
type ConfigSource interface {
	Current(ctx context.Context, monClientID string) (*registry.ConfigDoc, error)
}

// ConfigRoutes mounts GET /v1/config (protocol §4.2) on v1, behind
// RequireClientToken: a config document names every probe account and
// endpoint of the install, so it is only ever handed to an authenticated,
// enabled mon-client — and only its own, since the id comes from the token,
// never from the request.
func ConfigRoutes(v1 *gin.RouterGroup, auth ClientAuthenticator, cfgs ConfigSource) {
	v1.GET("/config", RequireClientToken(auth), func(c *gin.Context) { handleConfig(c, cfgs) })
}

// handleConfig answers with the caller's own config document. A mon-server
// that has not yet read anything from the panel has no document to serve
// (registry.ErrNoConfig): that is 503 config_not_ready rather than 404,
// because it is a temporary state of mon-server, not a statement about this
// mon-client — the right reaction is to come back, which is exactly what a
// mon-client does with a 5xx (protocol §1).
func handleConfig(c *gin.Context, cfgs ConfigSource) {
	mc := MonClientFrom(c)
	if mc == nil {
		// Unreachable behind RequireClientToken; a wiring mistake, not a
		// client error.
		Fail(c, http.StatusInternalServerError, "internal", "internal error")
		return
	}

	doc, err := cfgs.Current(c.Request.Context(), mc.Id)
	switch {
	case err == nil:
		c.JSON(http.StatusOK, doc)
	case errors.Is(err, registry.ErrNoConfig):
		Fail(c, http.StatusServiceUnavailable, "config_not_ready", "no config has been built yet")
	default:
		// A real failure (the database, or a stored document that no longer
		// decodes): its text can carry driver detail that has no business
		// reaching a mon-client, so it goes to the log instead.
		slog.Error("config: building the document failed", "monClientId", mc.Id, "error", err)
		Fail(c, http.StatusInternalServerError, "internal", "internal error")
	}
}
